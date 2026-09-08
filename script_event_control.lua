-- Event script: write one of the supported commands to Oven_Command.
require("user_library_gaggenau")
require("user.secrets")

local NETWORK = 0
local COMMAND_PARAM = "Oven_Command"
local DEBUG_PARAM = "Debug Logging"

local function debugEnabled()
  local ok, value = pcall(GetUserParam, NETWORK, DEBUG_PARAM)
  return ok and toboolean(value) or false
end

local function getParam(name)
  local ok, value = pcall(GetUserParam, NETWORK, name)
  return ok and value or nil
end

local function setParam(name, value)
  pcall(SetUserParam, NETWORK, name, value)
end

local dbg = debugEnabled()
local commandName = getParam(COMMAND_PARAM)
local command = gaggenau.GetCommand(commandName)
local credentials = secrets and secrets.gaggenau

if command and credentials and credentials.oven_host then
  if gaggenau.SendCommand(credentials.oven_host, command, dbg) then
    setParam(COMMAND_PARAM, "")
  end
elseif dbg then
  log("GAGGENAU: unsupported or unavailable Oven_Command '" .. tostring(commandName) .. "'")
end
