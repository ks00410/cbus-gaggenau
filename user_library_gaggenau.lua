require("user.secrets")

-- =============================================================================
-- SECTION 1 — REQUIRE / MODULE TABLE
-- =============================================================================

local json   = require("json")
local ws     = require("user.websocket")
local ffi    = require("ffi")
local encdec = require("encdec")

-- OpenSSL libcrypto — used for HMAC-SHA256 key derivation and HMAC tags.
local crypto = ffi.load("crypto")

ffi.cdef[[
  /* ── HMAC-SHA256 ─────────────────────────────────────────────────── */
  typedef struct evp_md_st   EVP_MD;
  typedef struct hmac_ctx_st HMAC_CTX;

  const EVP_MD *EVP_sha256(void);

  unsigned char *HMAC(const EVP_MD *evp_md,
                      const void *key, int key_len,
                      const unsigned char *d, size_t n,
                      unsigned char *md, unsigned int *md_len);
]]

local G = {}
gaggenau = G

-- =============================================================================
-- SECTION 2 — CONFIGURATION
-- =============================================================================

local CBUS_NETWORK = 0
local DEBUG_PARAM = "Debug Logging"
local DEVICE_ID = "cbus-gaggenau-001"
local APP_NAME = "CBusIntegration"
local CONNECT_TIMEOUT = 10

local USER_PARAMS = {
  "Oven_OperationState", "Oven_DoorState", "Oven_CurrentTemp",
  "Oven_Program", "Oven_TimeRemaining", "Oven_PreheatDone",
  "Oven_RemoteAllowed", "Oven_LastUpdated", "Cooktop_OperationState",
  "Cooktop_InUse", "Cooktop_LastUpdated"
}

-- =============================================================================
-- SECTION 3 — ID MAPS / LOOKUP TABLES
-- =============================================================================

-- These are typical UID values from homeconnect_websocket and may differ by
-- appliance model. The /ro/allDescriptionChanges response should be used to
-- build the actual map; the static map is only a fallback.
local ENTITY_KEY = {
  [10000] = "BSH.Common.Status.OperationState", -- typical example
  [10001] = "BSH.Common.Status.DoorState", -- typical example
  [10002] = "BSH.Common.Status.RemoteControlActive", -- typical example
  [10003] = "Cooking.Oven.Status.CurrentCavityTemperature", -- typical example
  [10004] = "BSH.Common.Root.ActiveProgram", -- typical example
  [10005] = "BSH.Common.Option.RemainingProgramTime", -- typical example
  [10006] = "Cooking.Oven.Event.PreheatFinished", -- typical example
  [10007] = "BSH.Common.Status.LocalControlActive", -- typical example
}

local KEY_LABEL = {
  ["BSH.Common.Status.OperationState"] = "Operation state",
  ["BSH.Common.Status.DoorState"] = "Door state",
  ["BSH.Common.Status.RemoteControlActive"] = "Remote allowed",
  ["Cooking.Oven.Status.CurrentCavityTemperature"] = "Current temperature",
  ["BSH.Common.Root.ActiveProgram"] = "Active programme",
  ["BSH.Common.Option.RemainingProgramTime"] = "Time remaining",
  ["Cooking.Oven.Event.PreheatFinished"] = "Preheat finished",
  ["BSH.Common.Status.LocalControlActive"] = "Cooktop in use",
}

local OPERATION_STATE = {
  ["BSH.Common.EnumType.OperationState.Inactive"] = "Inactive",
  ["BSH.Common.EnumType.OperationState.Ready"] = "Ready",
  ["BSH.Common.EnumType.OperationState.Run"] = "Running",
  ["BSH.Common.EnumType.OperationState.Pause"] = "Paused",
  ["BSH.Common.EnumType.OperationState.ActionRequired"] = "Action Required",
  ["BSH.Common.EnumType.OperationState.Finished"] = "Finished",
  ["BSH.Common.EnumType.OperationState.Error"] = "Error",
}

-- Typical command UIDs. Actual command UIDs are model-specific and should be
-- replaced with values from the downloaded description when required.
local COMMAND_UID = {
  light = 0,
  childLock = 0,
}

-- =============================================================================
-- SECTION 4 — MODULE STATE
-- =============================================================================

local _uidMap = {}
local _keyUidMap = {}
local _missingParamWarned = {}
local _activeCredentials = nil
local _activeMode = nil

-- =============================================================================
-- SECTION 5 — LOGGING HELPERS
-- =============================================================================

local function isDebuggingEnabled()
  local ok, value = pcall(GetUserParam, CBUS_NETWORK, DEBUG_PARAM)
  return ok and toboolean(value) or false
end

local function debuglog(message, dbg)
  if dbg then log("GAGGENAU: " .. tostring(message)) end
end

local function errorlog(message)
  log("GAGGENAU: " .. tostring(message))
end

-- =============================================================================
-- SECTION 6 — C-BUS I/O HELPERS
-- =============================================================================

local function safeGetUserParam(network, name)
  local ok, value = pcall(GetUserParam, network, name)
  return ok and value or nil
end

local function safeSetUserParam(network, name, value, dbg)
  if value == nil then return end
  local ok, err = pcall(SetUserParam, network, name, value)
  if not ok then
    local key = tostring(network) .. ":" .. name
    if dbg or not _missingParamWarned[key] then
      errorlog("UserParam '" .. name .. "' does not exist on network "
        .. tostring(network) .. " — skipping write: " .. tostring(err))
      _missingParamWarned[key] = true
    end
  end
end

-- =============================================================================
-- SECTION 7 — UTILITY FUNCTIONS
-- =============================================================================

local function number(value)
  if value == nil then return nil end
  return tonumber(value)
end

local function booleanNumber(value)
  if value == true or value == 1 or value == "1" or value == "true"
      or value == "True" then return 1 end
  return 0
end

local function nowText()
  return os.date("%d %b %Y, %H:%M:%S")
end

local function copyFallbackMap()
  local map = {}
  for uid, key in pairs(ENTITY_KEY) do map[uid] = key end
  return map
end

-- ── Home Connect AES framing ────────────────────────────────────────────────
-- Spec (from homeconnect_websocket/socket.py):
--   Key derivation:
--     enckey  = HMAC-SHA256(psk_bytes, b"ENC")    -- 32 bytes
--     mackey  = HMAC-SHA256(psk_bytes, b"MAC")    -- 32 bytes
--   Padding (send):
--     padded  = msg + 0x00 + random(padlen-2) + byte(padlen)
--     where padlen makes total length a multiple of 16, minimum 1 byte of random
--   Encrypt (send):
--     ciphertext = AES-256-CBC(enckey, iv, padded)
--     hmac_tag   = HMAC-SHA256(mackey, iv + 0x45 + last_tx_hmac + ciphertext)[0:16]
--     frame      = ciphertext + hmac_tag
--   Decrypt (receive):
--     ciphertext = frame[1 .. #frame-16]
--     hmac_tag   = frame[#frame-15 .. #frame]
--     verify HMAC-SHA256(mackey, iv + 0x45 + last_rx_hmac + ciphertext)[0:16] == hmac_tag
--     plain      = AES-256-CBC-decrypt(enckey, iv, ciphertext), strip padding
--
-- The IV is the per-appliance value from the downloaded profile (16 bytes).
-- CBC IV chaining across a session is handled by the stateful tx/rx HMAC state.

-- HMAC-SHA256: returns 32-byte binary digest.
local function hmacSha256(key, data)
  local out = ffi.new("unsigned char[32]")
  local outlen = ffi.new("unsigned int[1]", 32)
  crypto.HMAC(crypto.EVP_sha256(), key, #key, data, #data, out, outlen)
  return ffi.string(out, 32)
end

-- Decode a base64url string to binary (urlsafe: - and _ replace + and /).
local function b64urlDecode(s)
  local b64 = s:gsub("-", "+"):gsub("_", "/")
  -- Pad to multiple of 4.
  local pad = (4 - #b64 % 4) % 4
  b64 = b64 .. string.rep("=", pad)
  return encdec.base64dec(b64)
end

-- Derive enckey and mackey from the per-appliance PSK (base64url-encoded string
-- from the downloaded profile, or raw binary if already decoded).
local function deriveKeys(pskRaw)
  local enckey = hmacSha256(pskRaw, "ENC")
  local mackey = hmacSha256(pskRaw, "MAC")
  return enckey, mackey
end

-- Home Connect custom padding:
--   msg + 0x00 + random(padlen-2) + byte(padlen)
-- where padlen is chosen so that #msg + padlen is a multiple of 16, min padlen=2.
local function hcPad(msg)
  local padlen = 16 - (#msg % 16)
  if padlen < 2 then padlen = padlen + 16 end
  local tail = {}
  for i = 1, padlen - 2 do tail[i] = string.char(math.random(0, 255)) end
  tail[#tail + 1] = string.char(padlen)
  return msg .. "\0" .. table.concat(tail)
end

-- Strip the Home Connect padding from a decrypted block.
local function hcUnpad(data)
  if #data == 0 then return data end
  local padlen = string.byte(data, #data)
  if padlen > #data then return data end
  -- Find the 0x00 separator: it should be at position (#data - padlen + 1).
  local sepPos = #data - padlen + 1
  if string.byte(data, sepPos) ~= 0 then return data end
  return data:sub(1, sepPos - 1)
end

-- AES-256-CBC raw encrypt/decrypt without PKCS#7 padding, using direct
-- OpenSSL FFI calls (same crypto handle already loaded above).
-- We declare the required EVP cipher symbols here at module load time.

ffi.cdef[[
  typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
  typedef struct evp_cipher_st     EVP_CIPHER;
  EVP_CIPHER_CTX    *EVP_CIPHER_CTX_new(void);
  void               EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
  int                EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int pad);
  const EVP_CIPHER  *EVP_aes_256_cbc(void);
  int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key,
                         const unsigned char *iv);
  int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
  int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type,
                         void *impl, const unsigned char *key,
                         const unsigned char *iv);
  int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
  int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
]]

-- AES-256-CBC encrypt, no padding (input must be block-aligned).
local function aesCbcEncryptRaw(key, iv, data)
  local evp = crypto.EVP_CIPHER_CTX_new()
  crypto.EVP_EncryptInit_ex(evp, crypto.EVP_aes_256_cbc(), nil, key, iv)
  crypto.EVP_CIPHER_CTX_set_padding(evp, 0)   -- disable PKCS#7
  local inlen  = #data
  local outbuf = ffi.new("unsigned char[?]", inlen + 16)
  local outl   = ffi.new("int[1]")
  local total  = ffi.new("int[1]")
  crypto.EVP_EncryptUpdate(evp, outbuf, outl, data, inlen)
  total[0] = outl[0]
  crypto.EVP_EncryptFinal_ex(evp, outbuf + total[0], outl)
  total[0] = total[0] + outl[0]
  crypto.EVP_CIPHER_CTX_free(evp)
  return ffi.string(outbuf, total[0])
end

-- AES-256-CBC decrypt, no padding (strips nothing — caller uses hcUnpad).
local function aesCbcDecryptRaw(key, iv, data)
  local evp = crypto.EVP_CIPHER_CTX_new()
  crypto.EVP_DecryptInit_ex(evp, crypto.EVP_aes_256_cbc(), nil, key, iv)
  crypto.EVP_CIPHER_CTX_set_padding(evp, 0)   -- disable PKCS#7
  local inlen  = #data
  local outbuf = ffi.new("unsigned char[?]", inlen)
  local outl   = ffi.new("int[1]")
  local total  = ffi.new("int[1]")
  crypto.EVP_DecryptUpdate(evp, outbuf, outl, data, inlen)
  total[0] = outl[0]
  crypto.EVP_DecryptFinal_ex(evp, outbuf + total[0], outl)
  total[0] = total[0] + outl[0]
  crypto.EVP_CIPHER_CTX_free(evp)
  return ffi.string(outbuf, total[0])
end

-- Module-level AES session state (per appliance; reset on each new connection).
local _aesState = {
  enckey     = nil,
  mackey     = nil,
  iv         = nil,
  lastTxHmac = string.rep("\0", 32),
  lastRxHmac = string.rep("\0", 32),
}

-- Initialise AES session state from the appliance credentials.
-- psk64 = base64url-encoded PSK from the downloaded profile.
-- iv64  = base64url-encoded IV from the downloaded profile.
local function initAesSession(psk64, iv64)
  local pskRaw = b64urlDecode(psk64)
  local ivRaw  = b64urlDecode(iv64)
  _aesState.enckey, _aesState.mackey = deriveKeys(pskRaw)
  _aesState.iv         = ivRaw
  _aesState.lastTxHmac = string.rep("\0", 32)
  _aesState.lastRxHmac = string.rep("\0", 32)
end

-- Encrypt a plaintext JSON string using the Home Connect AES framing.
-- Returns the binary frame (ciphertext + 16-byte HMAC tag).
local function aesEncrypt(plaintext)
  if not _aesState.enckey then
    log("GAGGENAU: AES session not initialised — call initAesSession first")
    return plaintext
  end
  local padded    = hcPad(plaintext)
  local cipher    = aesCbcEncryptRaw(_aesState.enckey, _aesState.iv, padded)
  local hmacInput = _aesState.iv .. "\x45" .. _aesState.lastTxHmac .. cipher
  local tag       = hmacSha256(_aesState.mackey, hmacInput):sub(1, 16)
  _aesState.lastTxHmac = hmacSha256(_aesState.mackey, hmacInput)
  return cipher .. tag
end

-- Decrypt a binary frame received from the appliance.
-- Returns the plaintext JSON string, or nil on HMAC verification failure.
local function aesDecrypt(frame)
  if not _aesState.mackey then
    log("GAGGENAU: AES session not initialised — call initAesSession first")
    return frame
  end
  if #frame < 17 then
    log("GAGGENAU: AES frame too short (" .. #frame .. " bytes)")
    return nil
  end
  local cipher  = frame:sub(1, #frame - 16)
  local rxTag   = frame:sub(#frame - 15)
  local hmacInput = _aesState.iv .. "\x45" .. _aesState.lastRxHmac .. cipher
  local expected  = hmacSha256(_aesState.mackey, hmacInput):sub(1, 16)
  if rxTag ~= expected then
    log("GAGGENAU: AES HMAC verification failed — frame rejected")
    return nil
  end
  _aesState.lastRxHmac = hmacSha256(_aesState.mackey, hmacInput)
  local plain = aesCbcDecryptRaw(_aesState.enckey, _aesState.iv, cipher)
  return hcUnpad(plain)
end

local function encodeMessage(message, credentials)
  local plaintext = json.encode(message)
  if _activeMode == "AES" then return aesEncrypt(plaintext) end
  return plaintext
end

local function decodeMessage(payload, credentials)
  local plaintext = payload
  if _activeMode == "AES" then plaintext = aesDecrypt(payload) end
  local ok, message = pcall(json.decode, plaintext)
  return ok and message or nil
end

local function sendMessage(conn, message, credentials, dbg)
  local payload = encodeMessage(message, credentials)
  local ok, err = pcall(conn.send, conn, payload)
  if not ok then errorlog("WebSocket send failed: " .. tostring(err)); return false end
  debuglog("TX " .. json.encode(message), dbg)
  return true
end

local function receiveMessage(conn, credentials, dbg)
  local ok, payload = pcall(conn.receive, conn)
  if not ok or payload == nil then
    errorlog("WebSocket receive failed: " .. tostring(payload))
    return nil
  end
  local message = decodeMessage(payload, credentials)
  if not message then errorlog("Invalid Home Connect JSON response"); return nil end
  debuglog("RX " .. tostring(payload), dbg)
  return message
end

local function nextMessage(sid, msgid, resource, version, action, data)
  return { sID = sid, msgID = msgid, resource = resource, version = version,
    action = action, data = data }
end

local function learnDescriptions(message, dbg)
  if not message or not message.data then return end
  for _, entity in ipairs(message.data) do
    local uid = entity.uid
    local key = entity.key or entity.name or entity.entityKey
    if uid and key then
      _uidMap[uid] = key
      _keyUidMap[key] = uid
      debuglog("Mapped UID " .. tostring(uid) .. " to " .. tostring(key), dbg)
    end
  end
end

local function keyForUid(uid)
  return _uidMap[uid] or ENTITY_KEY[uid]
end

local function uidForKey(key)
  return _keyUidMap[key] or (function()
    for uid, mapped in pairs(_uidMap) do if mapped == key then return uid end end
    for uid, mapped in pairs(ENTITY_KEY) do if mapped == key then return uid end end
  end)()
end

local function valuesByKey(values)
  local result = {}
  for _, entity in ipairs(values or {}) do
    local key = keyForUid(entity.uid)
    if key then result[key] = entity.value end end
  return result
end

-- =============================================================================
-- SECTION 8 — DERIVED VALUE FUNCTIONS
-- =============================================================================

local function operationState(value)
  return OPERATION_STATE[tostring(value)] or value
end

local function preheatFlag(value)
  return booleanNumber(value)
end

local function remoteAllowed(value)
  return booleanNumber(value)
end

local function cooktopInUse(value)
  return booleanNumber(value)
end

-- =============================================================================
-- SECTION 9 — WEBSOCKET CONNECT + MESSAGE HELPERS
-- =============================================================================

local function credentialsFor(host)
  local credentials = secrets and secrets.gaggenau
  if not credentials then errorlog("secrets.gaggenau is not configured"); return nil end
  if host == credentials.oven_host then
    return credentials, credentials.oven_mode or "AES",
           credentials.oven_key, credentials.oven_iv
  elseif host == credentials.cooktop_host then
    return credentials, credentials.cooktop_mode or "AES",
           credentials.cooktop_key, credentials.cooktop_iv
  end
  errorlog("No Gaggenau credentials configured for host " .. tostring(host))
  return nil
end

function G.Connect(host, dbg)
  local credentials, mode, psk64, iv64 = credentialsFor(host)
  if not credentials then return nil end
  _activeCredentials = credentials
  _activeMode = mode
  -- Initialise AES session state whenever we open a new connection.
  if mode == "AES" then
    if not psk64 or not iv64 then
      errorlog("AES mode selected but oven_key or oven_iv missing from secrets.gaggenau")
      return nil
    end
    initAesSession(psk64, iv64)
  end
  local scheme = mode == "TLS" and "wss://" or "ws://"
  local path = mode == "TLS" and ":443/homeconnect" or "/homeconnect"
  local conn = ws.new()
  local ok, err = pcall(conn.connect, conn, scheme .. host .. path)
  if not ok then errorlog("Connect failed: " .. tostring(err)); return nil end

  local init = receiveMessage(conn, credentials, dbg)
  if not init or not init.sID then G.Disconnect(conn); return nil end
  local sid = init.sID
  local msgid = init.msgID or 1
  local edMsgID = init.data and init.data[1] and init.data[1].edMsgID
  debuglog("Initial message received, edMsgID=" .. tostring(edMsgID), dbg)

  if not sendMessage(conn, nextMessage(sid, msgid, "/ei/initialValues", 2,
      "RESPONSE", {{ deviceType = "Application", deviceName = APP_NAME,
      deviceID = DEVICE_ID }}), credentials, dbg) then G.Disconnect(conn); return nil end
  msgid = msgid + 1

  if not sendMessage(conn, nextMessage(sid, msgid, "/ci/services", 1,
      "GET", {}), credentials, dbg) then G.Disconnect(conn); return nil end
  msgid = msgid + 1
  local services = receiveMessage(conn, credentials, dbg)
  if not services then G.Disconnect(conn); return nil end

  if not sendMessage(conn, nextMessage(sid, msgid, "/ro/allDescriptionChanges", 1,
      "GET", {}), credentials, dbg) then G.Disconnect(conn); return nil end
  msgid = msgid + 1
  local descriptions = receiveMessage(conn, credentials, dbg)
  if descriptions then learnDescriptions(descriptions, dbg) end

  if not sendMessage(conn, nextMessage(sid, msgid, "/ro/allMandatoryValues", 1,
      "GET", {}), credentials, dbg) then G.Disconnect(conn); return nil end
  msgid = msgid + 1
  local mandatory = receiveMessage(conn, credentials, dbg)
  if not mandatory then G.Disconnect(conn); return nil end

  sendMessage(conn, nextMessage(sid, msgid, "/ei/deviceReady", 2,
    "NOTIFY", {}), credentials, dbg)
  return conn, sid, msgid + 1, mandatory.data or {}
end

function G.GetAllValues(conn, sid, msgid, dbg)
  local message = nextMessage(sid, msgid, "/ro/allMandatoryValues", 1, "GET", {})
  if not sendMessage(conn, message, _activeCredentials, dbg) then return nil end
  local response = receiveMessage(conn, _activeCredentials, dbg)
  return response and response.data or nil
end

function G.Disconnect(conn)
  if conn then pcall(conn.close, conn) end
  _activeCredentials = nil
  _activeMode = nil
end

local function postCommand(host, command, dbg)
  local conn, sid, msgid = G.Connect(host, dbg)
  if not conn then return false end
  local uid = uidForKey(command.key)
  if not uid or uid == 0 then
    errorlog("No UID known for command key " .. tostring(command.key))
    G.Disconnect(conn); return false
  end
  local credentials = _activeCredentials
  local sent = sendMessage(conn, nextMessage(sid, msgid, "/ro/values", 1, "POST",
    {{ uid = uid, value = command.value }}), credentials, dbg)
  if sent then receiveMessage(conn, credentials, dbg) end
  G.Disconnect(conn)
  return sent
end

-- =============================================================================
-- SECTION 10 — PAYLOAD PARSER (ENTITY VALUE EXTRACTION)
-- =============================================================================

function G.ParseValues(values)
  local raw = valuesByKey(values)
  return {
    operationState = operationState(raw["BSH.Common.Status.OperationState"]),
    doorState = raw["BSH.Common.Status.DoorState"],
    currentTemp = number(raw["Cooking.Oven.Status.CurrentCavityTemperature"]),
    program = raw["BSH.Common.Root.ActiveProgram"],
    timeRemaining = number(raw["BSH.Common.Option.RemainingProgramTime"]),
    preheatDone = preheatFlag(raw["Cooking.Oven.Event.PreheatFinished"]),
    remoteAllowed = remoteAllowed(raw["BSH.Common.Status.RemoteControlActive"]),
    cooktopOperationState = operationState(raw["BSH.Common.Status.OperationState"]),
    cooktopInUse = cooktopInUse(raw["BSH.Common.Status.LocalControlActive"]),
  }
end

function G.WriteValues(values, dbg, appliance)
  local parsed = G.ParseValues(values)
  local stamp = nowText()
  if appliance == "cooktop" then
    safeSetUserParam(CBUS_NETWORK, "Cooktop_OperationState", parsed.cooktopOperationState, dbg)
    safeSetUserParam(CBUS_NETWORK, "Cooktop_InUse", parsed.cooktopInUse, dbg)
    safeSetUserParam(CBUS_NETWORK, "Cooktop_LastUpdated", stamp, dbg)
    return
  end
  safeSetUserParam(CBUS_NETWORK, "Oven_OperationState", parsed.operationState, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_DoorState", parsed.doorState, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_CurrentTemp", parsed.currentTemp, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_Program", parsed.program, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_TimeRemaining", parsed.timeRemaining, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_PreheatDone", parsed.preheatDone, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_RemoteAllowed", parsed.remoteAllowed, dbg)
  safeSetUserParam(CBUS_NETWORK, "Oven_LastUpdated", stamp, dbg)
end

function G.SendCommand(host, command, dbg)
  return postCommand(host, command, dbg)
end

function G.GetCommand(commandName)
  if commandName == "light_on" then
    return { key = "Cooking.Oven.Setting.Cavity.Light", value = "BSH.Common.EnumType.LightState.On" }
  elseif commandName == "light_off" then
    return { key = "Cooking.Oven.Setting.Cavity.Light", value = "BSH.Common.EnumType.LightState.Off" }
  elseif commandName == "child_lock_on" then
    return { key = "BSH.Common.Setting.ChildLock", value = true }
  elseif commandName == "child_lock_off" then
    return { key = "BSH.Common.Setting.ChildLock", value = false }
  end
  return nil
end

-- =============================================================================
-- SECTION 11 — RESIDENT POLL
-- =============================================================================

function G.Resident_Poll()
  -- This is deliberately the only isDebuggingEnabled() call in a poll.
  local dbg = isDebuggingEnabled()
  local credentials = secrets and secrets.gaggenau
  if not credentials then errorlog("Missing secrets.gaggenau"); return end
  local hosts = {
    { host = credentials.oven_host, appliance = "oven" },
    { host = credentials.cooktop_host, appliance = "cooktop" },
  }
  for _, target in ipairs(hosts) do
    if target.host then
      local conn, sid, msgid, values = G.Connect(target.host, dbg)
      if conn then
        if not values then values = G.GetAllValues(conn, sid, msgid, dbg) end
        if values then G.WriteValues(values, dbg, target.appliance) end
        G.Disconnect(conn)
      end
    end
  end
end

return G
