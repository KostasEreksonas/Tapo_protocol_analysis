-- -*- coding: utf-8 -*-
-- Dissector for proprietary communication protocol found on TP-Link Tapo devices
-- Copyright (C) 2026 Kostas Ereksonas
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <https://www.gnu.org/licenses/>.

-- Load JSON dissector
local json = Dissector.get("json")

-- Keep HTTP messages intact when dissecting TP-Link proprietary messages on port TCP/8800
local http = DissectorTable.get("tcp.port"):get_dissector(80)

-- Header length of discovery packets
local HEADER_LEN_DISCOVERY = 16

local tapo_proto = Proto("tapo", "TP-Link Tapo Protocol")

-- Discovery message fields
local tapo_header = ProtoField.bytes("tapo.header", "Header RAW")
local tapo_signature = ProtoField.uint32("tapo.signature", "Signature of Discovery Message", base.HEX_DEC)
local tapo_payload_length = ProtoField.uint16("tapo.payload_length", "Payload Length of Discovery Message", base.DEC_HEX)
local tapo_unknown_1 = ProtoField.uint16("tapo.unknown_1", "Unknown Field 1", base.HEX_DEC)
local tapo_unknown_2 = ProtoField.uint32("tapo.unknown_2", "Unknown Field 2", base.HEX_DEC)
local tapo_crc32_checksum = ProtoField.uint32("tapo.crc32", "CRC32 cheksum (header + payload)", base.HEX_DEC)
local tapo_payload_json_raw = ProtoField.string("tapo.data", "Raw JSON Message") 

-- Content message fields
local tapo_device_stream_boundary = ProtoField.string("tapo.device_stream_boundary", "Device Stream Boundary")
local tapo_content_type = ProtoField.string("tapo.content_type", "Content Type")
local tapo_content_length = ProtoField.string("tapo.content_length", "Content Length")
local tapo_x_session_id = ProtoField.string("tapo.session_id", "Session ID")
local tapo_x_if_encrypt = ProtoField.string("tapo.encrypted", "Ecryption Flag")

tapo_proto.fields = {
    -- Discovery message fields
    tapo_header,
    tapo_payload_json_raw,
    tapo_signature,
    tapo_payload_length,
    tapo_unknown_1,
    tapo_unknown_2,
    tapo_crc32_checksum,
    -- Content message fields
    tapo_device_stream_boundary,
    tapo_content_type,
    tapo_content_length,
    tapo_x_session_id,
    tapo_x_if_encrypt
}

local function get_udp_len(tvb)
    return tvb:len()
end

local function udp_dissect_json_pdu(tvb, pinfo, subtree)
    -- Dissect discovery and management packets
    -- Add raw header to the protocol tree
    subtree:add(tapo_header, tvb(0, 16))

    -- Parse separate header fields and put into a subtree
    local htree = subtree:add(tapo_proto, tvb(0, HEADER_LEN_DISCOVERY), "TAPO Discovery Packet Header")
    htree:add(tapo_signature, tvb(0, 4))
    htree:add(tapo_payload_length, tvb(4, 2))
    htree:add(tapo_unknown_1, tvb(6, 2))
    htree:add(tapo_unknown_2, tvb(8, 4))
    htree:add(tapo_crc32_checksum, tvb(12, 4))

    -- Save payload as JSON
    local json_tvb
    json_tvb = tvb(HEADER_LEN_DISCOVERY, tvb:len() - HEADER_LEN_DISCOVERY)

	-- Decode JSON object using built-in dissector
	json:call(json_tvb:tvb(), pinfo, subtree)
	
    -- Add JSON payload to the protocol tree
    subtree:add(tapo_payload_json_raw, json_tvb)

    -- Update protocol info
	pinfo.cols.protocol = tapo_proto.name
    pinfo.cols.info = "Discovery Packet "

	return tvb:len()
end

local function parse_header(tvb)
    -- Parse message header
    local byte_string = tvb:raw()
    local delimiter = "\x0d\x0a\x0d\x0a"

    -- Get header length
    local first, last = string.find(byte_string, delimiter, 1, true)
    local header_length = last

    -- Parse header fields that has variable length
    local header_string = tvb(30, header_length):string()
    local header_fields = {}

    for split in string.gmatch(header_string, "(.-)\r\n") do
        for key, value in string.gmatch(split, "([^:]+):([^\r\n]+)") do -- Key: value\r\n
            header_fields[key] = value
        end
    end

    -- Get length of a payload
    local payload_length = tonumber(header_fields["Content-Length"])

    if header_length == nil then
        return 0
    end

    return header_length, payload_length
end

local function get_content_length(tvb, pinfo, offset)
    -- Get length of Tapo protocol message (header + payload)    
    local header_length, payload_length = parse_header(tvb)

    if header_length == nil then
        pinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
    elseif payload_length == nil then
        return 0
    end

    return header_length + payload_length + 2
end

local function build_content_message_header(tvb, header_length, htree)
    -- Build content message header
    local offset = 30
    local header_string = tvb(offset, header_length):string()

    for split in string.gmatch(header_string, "(.-)\r\n") do
        for key, value in string.gmatch(split, "([^:]+):([^\r\n]+)") do -- Key: value\r\n
            htree:add(key, ":", value)
        end
    end
end

local function dissect_content_pdu(tvb, pinfo, subtree)
    -- Dissect one Tapo PDU
    local header_length, payload_length = parse_header(tvb)
    
    -- Populate message header tree
    local htree = subtree:add(tapo_proto, tvb(0, header_length), "TAPO Content Packet Header")
    htree:add(tapo_device_stream_boundary, tvb(0, 28))
    build_content_message_header(tvb, header_length, htree)
    
    -- Parse payload (JSON or encrypted media)
    if tvb(header_length, 1):uint() == 0x7b then
        local json_tvb
        json_tvb = tvb(header_length, payload_length)
        -- Raw JSON text
		subtree:add(tapo_payload_json_raw, json_tvb)

		-- Decode JSON object using built-in dissector
		json:call(json_tvb:tvb(), pinfo, subtree)

        -- Packet information
        pinfo.cols.info = "JSON Payload "
    else
        local ptree = subtree:add(tapo_proto, tvb(header_length, payload_length), "TAPO Encrypted Payload")

        -- Packet information
        pinfo.cols.info = "Encrypted Payload "
    end

    -- Message ends with a newline
    subtree:add(tapo_proto, tvb(header_length + payload_length, 2), "Newline")

    -- Add information to pinfo
    pinfo.cols.protocol = tapo_proto.name
end

function tapo_proto.dissector(tvb, pinfo, tree)
    local subtree = tree:add(tapo_proto, tvb(), "TAPO Communication Protocol")
    if tvb(0, 4):uint() == 0x02000001 then
        -- Dissect as TP-Link discovery packets on port UDP/20002
        dissect_tcp_pdus(tvb, subtree, HEADER_LEN_DISCOVERY, get_udp_len, udp_dissect_json_pdu, true)
    elseif tvb(0, 4):string() == "HTTP" then
        -- Port TCP/8800 has some HTTP messages as well. Leave them intact.
        http:call(tvb, pinfo, tree)
    elseif tvb(0, 4):uint() == 0x2d2d2d2d then
        -- Dissect video stream and communication service on port TCP/8800
        dissect_tcp_pdus(tvb, subtree, 0, get_content_length, dissect_content_pdu, true)
    end
end

local udp_table = DissectorTable.get("udp.port")
udp_table:add(20002, tapo_proto)
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(8800, tapo_proto)