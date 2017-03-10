local skynet = require "skynet"
local socket = require "socket"
local socketchannel = require "socketchannel"

local sutil = require "utils.util"
local table = table
local tinsert = table.insert
local tconcat = table.concat
local string = string
local assert = assert

--TODO 缓存table的表头，避免每次都要解析
local NULL = "\0"
local pg = {}
local command = {}
local meta = {
	__index = command,
	-- DO NOT close channel in __gc
}

local util = {}

local AUTH_TYPE = {
	NO_AUTH = 0,
	PLAIN_TEXT = 3,
	MD5 = 5,
}

local PG_TYPES = {
	[16] = "boolean",
	[17] = "bytea",
	[20] = "number",
	[21] = "number",
	[23] = "number",
	[700] = "number",
	[701] = "number",
	[1700] = "number",
	[114] = "json",
	[3802] = "json",
	[1000] = "array_boolean",
	[1005] = "array_number",
	[1007] = "array_number",
	[1016] = "array_number",
	[1021] = "array_number",
	[1022] = "array_number",
	[1231] = "array_number",
	[1009] = "array_string",
	[1015] = "array_string",
	[1002] = "array_string",
	[1014] = "array_string",
	[2951] = "array_string",
	[199] = "array_json",
	[3807] = "array_json"
}
local type_deserializers = {
	json = function(self, val, name)
		local decode_json
		decode_json = require("pgmoon.json").decode_json
		return decode_json(val)
	end,
	bytea = function(self, val, name)
		return self:decode_bytea(val)
	end,
	array_boolean = function(self, val, name)
		local decode_array
		decode_array = require("pgmoon.arrays").decode_array
		return decode_array(val, tobool)
	end,
	array_number = function(self, val, name)
		local decode_array
		decode_array = require("pgmoon.arrays").decode_array
		return decode_array(val, tonumber)
	end,
	array_string = function(self, val, name)
		local decode_array
		decode_array = require("pgmoon.arrays").decode_array
		return decode_array(val)
	end,
	array_json = function(self, val, name)
		local decode_array
		decode_array = require("pgmoon.arrays").decode_array
		local decode_json
		decode_json = require("pgmoon.json").decode_json
		return decode_array(val, decode_json)
	end,
	hstore = function(self, val, name)
		local decode_hstore
		decode_hstore = require("pgmoon.hstore").decode_hstore
		return decode_hstore(val)
	end
}

local pg_auth_cmd = {}
local read_response = nil

util.cal_len = function(thing, t)
	if t == nil then
		t = type(thing)
	end
	if "string" == t then
		return #thing
	elseif "table" == t then
		local l = 0
		for i = 1, #thing do
			local inner = thing[i]
			local inner_t = type(inner)
			if inner_t == "string" then
				l = l + #inner
			else
				l = l + util.cal_len(inner, inner_t)
			end
		end
		return l
	else
		return error("don't know how to calculate length of " .. tostring(t))
	end
end

function util.flip(t)
	local keys = {}
	for k,v in pairs(t) do
		tinsert(keys, k)
	end
	for i=1, #keys do
		local k = keys[i]
		t[t[k]] = k
	end
	return t
end

local MSG_TYPE = {
	status = "S",
	auth = "R",
	backend_key = "K",
	ready_for_query = "Z",
	query = "Q",
	notice = "N",
	notification = "A",
	password = "p",
	row_description = "T",
	data_row = "D",
	command_complete = "C",
	error = "E"
}
local ERROR_TYPES = {
	severity = "S",
	code = "C",
	message = "M",
	position = "P",
	detail = "D",
	schema = "s",
	table = "t",
	constraint = "n"
}
MSG_TYPE = util.flip(MSG_TYPE)
ERROR_TYPES = util.flip(ERROR_TYPES)

pg_auth_cmd[AUTH_TYPE.NO_AUTH] = function(fd, data)
	return true
end
pg_auth_cmd[AUTH_TYPE.PLAIN_TEXT] = function(so, user, password)
	local data = {password, NULL}
	util.send_message(so, MSG_TYPE.password, data)
	return true
end

--TODO md5 password
pg_auth_cmd[AUTH_TYPE.MD5] = function(so, user, password)
end

function pg_auth_cmd:set_auth_type(auth_type)
	self.auth_type = auth_type
end

function pg_auth_cmd:send_auth_info(so, db_conf)
	local auth_type = self.auth_type
	local f = self[auth_type]
	assert(f, string.format("auth_type func not exist %s", self.auth_type))
	print(auth_type, "send_auth_info")
	f(so, db_conf.user, db_conf.password)
end

function pg_auth_cmd:set_ready_for_query()
	self.ready_for_query = true
end

function pg_auth_cmd:wait_ready(so)
	while true do
		so:response(read_response)
		if self.ready_for_query then
			break
		end
	end
end

setmetatable(pg_auth_cmd, pg_auth_cmd)

function util.encode_int(n, bytes)
	if bytes == nil then
		bytes = 4
	end
	if 4 == bytes then
		local a = n & 0xff
		local b = (n >> 8) & 0xff
		local c = (n >> 16) & 0xff
		local d = (n >> 24) & 0xff
		return string.char(d, c, b, a)
	else
		return error("don't know how to encode " .. tostring(bytes) .. " byte(s)")
	end
end

function util.decode_int(str, bytes)
	if bytes == nil then
		bytes = #str
	end
	if 4 == bytes then
		local d, c, b, a = str:byte(1, 4)
		return a + (b << 8) + (c << 16) + (d << 24)
	elseif 2 == bytes then
		local b, a = str:byte(1, 2)
		return a + (b << 8)
	else
		return error("don't know how to decode " .. tostring(bytes) .. " byte(s)")
	end
end

function util.send_message(so, msg_type, data, len)
	if len == nil then
		len = util.cal_len(data)
	end
	len = len + 4
	local req_data = {msg_type, util.encode_int(len), data}
	local req_msg = util.flatten(req_data)
	return so:request(req_msg, read_response)
end

local function parse_row_desc(row_desc)
	local num_fields = util.decode_int(row_desc:sub(1, 2))
	local offset = 3
	local fields = {}

	for i = 1, num_fields do
		local name = row_desc:match("[^%z]+", offset)
		offset = offset + #name + 1
		local data_type = util.decode_int(row_desc:sub(offset + 6, offset + 6 + 3))
		data_type = PG_TYPES[data_type] or "string"
		local format = util.decode_int(row_desc:sub(offset + 16, offset + 16 + 1))
		assert(0 == format, "don't know how to handle format")
		offset = offset + 18
		local info = {
			name,
			data_type
		}
		tinsert(fields, info)
	end

	return fields
end
local function parse_row_data(data_row, fields)
	local num_fields = util.decode_int(data_row:sub(1, 2))
	print(num_fields, "num_fields")
	local out = {}
	local offset = 3
	for i = 1, num_fields do
		local to_continue = false
		repeat
			local field = fields[i]
			if not (field) then
				to_continue = true
				break
			end
			local field_name, field_type
			field_name, field_type = field[1], field[2]
			--print(field_name, field_type, "field")
			local len = util.decode_int(data_row:sub(offset, offset + 3))
			offset = offset + 4
			if len < 0 then
				--TODO null 处理
				if self.convert_null then
					out[field_name] = NULL
				end
				to_continue = true
				break
			end
			local value = data_row:sub(offset, offset + len - 1)
			offset = offset + len
			if "number" == field_type then
				value = tonumber(value)
			elseif "boolean" == field_type then
				value = value == "t"
			elseif "string" == field_type then
				value = value
			else
				do
					local fn = type_deserializers[field_type]
					if fn then
						value = fn(value, field_type)
					end
				end
			end
			out[field_name] = value
			to_continue = true
		until true
		if not to_continue then
			break
		end
	end
	return out
end

-- pg response
local pg_command = {}

pg_command[MSG_TYPE.auth] = function(self, data)
	local auth_type = util.decode_int(data, 4)
	print(auth_type, "auth_type")
	if auth_type ~= AUTH_TYPE.NO_AUTH then
		pg_auth_cmd:set_auth_type(auth_type)
	end
	return true 
end

pg_command[MSG_TYPE.status] = function(self, data)
	print("MSG_TYPE.status", data)
	return true
end

pg_command[MSG_TYPE.backend_key] = function(self, data)
	return true
end

pg_command[MSG_TYPE.ready_for_query] = function(self, data)
	print("MSG_TYPE.ready_for_query")
	pg_auth_cmd:set_ready_for_query()
	return true
end

pg_command[MSG_TYPE.query] = function(self, data)
end

pg_command[MSG_TYPE.notice] = function(self, data)
end

pg_command[MSG_TYPE.notification] = function(self, data)
end

pg_command[MSG_TYPE.password] = function(self, data)
end

pg_command[MSG_TYPE.row_description] = function(self, data)
	print("MSG_TYPE.row_description", data)
	if data == nil then
		return false
	else
		local fields = parse_row_desc(data)
		sutil.dump(fields, "fields")
		self.row_desc = data
		self.row_data = {}
		return true, data
	end
end

pg_command[MSG_TYPE.data_row] = function(self, data)
	tinsert(self.row_data, data)
	print("MSG_TYPE.data_row")
	return true
end

pg_command[MSG_TYPE.command_complete] = function(self, data)
	print("MSG_TYPE.command_complete")
	self.command_complete = true
	return true
end

pg_command[MSG_TYPE.error] = function(self, err_msg)
	local severity, message, detail, position
	local error_data = { }
	local offset = 1
	while offset <= #err_msg do
		local t = err_msg:sub(offset, offset)
		local str = err_msg:match("[^%z]+", offset + 1)
		if not (str) then
			break
		end
		offset = offset + (2 + #str)
		do
			local field = ERROR_TYPES[t]
			if field then
				error_data[field] = str
			end
		end
		if ERROR_TYPES.severity == t then
			severity = str
		elseif ERROR_TYPES.message == t then
			message = str
		elseif ERROR_TYPES.position == t then
			position = str
		elseif ERROR_TYPES.detail == t then
			detail = str
		end
	end
	local msg = tostring(severity) .. ": " .. tostring(message)
	if position then
		msg = tostring(msg) .. " (" .. tostring(position) .. ")"
	end
	if detail then
		msg = tostring(msg) .. "\n" .. tostring(detail)
	end
	return false, msg, error_data
end

function pg_command:read_response()
	local so = self.so
	while not self.command_complete do
		so:response(read_response)
	end
	self.command_complete = false
	return self.row_desc, self.row_data
end

setmetatable(pg_command, pg_command)

read_response = function(fd)
	local t = fd:read(1)
	local len = fd:read(4)
	len = util.decode_int(len)
	len = len - 4
	local msg = fd:read(len)
	print(t)
	local f = pg_command[t]
	assert(f, string.format("pg response func handle not exist: %s", t))
	return f(pg_command, msg)
end

function util.__flatten(t, buffer)
	local ttype = type(t)
	if "string" == ttype then
		buffer[#buffer + 1] = t
	elseif "table" == ttype then
		for i = 1, #t do
			local thing = t[i]
			util.__flatten(thing, buffer)
		end
	end
end

function util.flatten(t)
	local buffer = { }
	util.__flatten(t, buffer)
	return tconcat(buffer)
end

--util fuctions


local function pg_login(conf)
	return function(so)
		local data = {
			util.encode_int(196608),
			"user",
			NULL,
			conf.user,
			NULL,
			"database",
			NULL,
			conf.database,
			NULL,
			"application_name",
			NULL,
			"skynet",
			NULL,
			NULL
		}
		print(sutil.dump(so))
		local req_msg = util.flatten({util.encode_int(util.cal_len(data)+4), data})
		pg_command.so = so
		so:request(req_msg, read_response)
		pg_auth_cmd:send_auth_info(so, conf)
		pg_auth_cmd:wait_ready(so)
	end
end

function pg.connect(db_conf)
	local channel = socketchannel.channel {
		host = db_conf.host or "127.0.0.1",
		port = db_conf.port or 5432,
		auth = pg_login(db_conf),
		nodelay = true,
	}
	-- try connect first only once
	channel:connect(true)
	return setmetatable( { channel }, meta )
end

local compose_message = {}
compose_message[MSG_TYPE.query] = function(q)
	return {q, NULL}
end

setmetatable(command, { __index = function(t, k)
	local cmd = k
	local f = function(self, v, ...)
		local msg_type = MSG_TYPE[cmd]
		local compose_func = compose_message[msg_type]
		local data = compose_func(v, ...)
		util.send_message(self[1], msg_type, data)
		return pg_command:read_response()
	end
	t[k] = f
	return f
end})


return pg
