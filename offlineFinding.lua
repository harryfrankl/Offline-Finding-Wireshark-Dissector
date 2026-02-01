-- =============================================================================
-- Apple Offline Finding Protocol Dissector for Wireshark
-- =============================================================================
--
-- SPDX-License-Identifier: GPL-3.0-or-later
--
-- Copyright (C) 2025 Harry Frankl
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program. If not, see <https://www.gnu.org/licenses/>.
--
-- =============================================================================
-- Protocol Reference: Apple's Offline Finding (OF) protocol used by
-- Find My network (AirTags, Find My-enabled devices)
--
-- Buffer Structure (as received from manufacturer_company_id dissector table):
-- Note: Company ID is already stripped by Wireshark before passing to this dissector
--
--   Offset  Size  Field
--   [0]     1     Type (0x12 - Offline Finding)
--   [1]     1     Payload Length (0x19 = 25 bytes)
--   [2]     1     Status Byte (battery[7:6] + reserved[5:0])
--   [3-24]  22    Public Key Fragment (bytes 6-27 of EC P-224 key)
--   [25]    1     Key Hint (derived from first byte of key)
--   [26]    1     Rotation Counter
--
-- Full 28-byte EC P-224 public key reconstruction:
--   BLE Random Address (6 bytes) + Key Fragment (22 bytes) = Full Key (28 bytes)
--
-- Version: 1.0.0
-- Repository: https://github.com/harryfrankl/Offline-Finding-Wireshark-Dissector
-- =============================================================================

-- =============================================================================
-- PROTOCOL DEFINITION
-- =============================================================================

local protoOfflineFinding = Proto("offlineFinding", "Apple Offline Finding Protocol")

local APPLE_COMPANY_ID = 0x004C
local OF_TYPE = 0x12
local EXPECTED_PAYLOAD_LEN = 0x19
local PUBLIC_KEY_FRAG_LEN = 22
local MIN_BUFFER_LEN = 3

local batteryLevels = {
    [0] = "Full",
    [1] = "Medium",
    [2] = "Low",
    [3] = "Critical"
}

-- =============================================================================
-- FIELD DEFINITIONS
-- =============================================================================

local fieldType = ProtoField.uint8(
    "offlineFinding.type",
    "Advertisement Type",
    base.HEX
)

local fieldPayloadLength = ProtoField.uint8(
    "offlineFinding.payloadLength",
    "Payload Length",
    base.DEC
)

local fieldStatus = ProtoField.uint8(
    "offlineFinding.status",
    "Status Byte",
    base.HEX
)

local fieldBatteryLevel = ProtoField.uint8(
    "offlineFinding.status.battery",
    "Battery Level",
    base.DEC,
    batteryLevels,
    0xC0
)

local fieldReservedBits = ProtoField.uint8(
    "offlineFinding.status.reserved",
    "Reserved Bits",
    base.HEX,
    nil,
    0x3F
)

local fieldKeyFragment = ProtoField.bytes(
    "offlineFinding.keyFragment",
    "Public Key Fragment"
)

local fieldFullPublicKey = ProtoField.string(
    "offlineFinding.fullPublicKey",
    "Full EC P-224 Public Key"
)

local fieldKeyHint = ProtoField.uint8(
    "offlineFinding.keyHint",
    "Key Hint",
    base.HEX
)

local fieldCounter = ProtoField.uint8(
    "offlineFinding.counter",
    "Rotation Counter",
    base.DEC
)

protoOfflineFinding.fields = {
    fieldType,
    fieldPayloadLength,
    fieldStatus,
    fieldBatteryLevel,
    fieldReservedBits,
    fieldKeyFragment,
    fieldFullPublicKey,
    fieldKeyHint,
    fieldCounter
}

-- =============================================================================
-- FIELD EXTRACTORS
-- =============================================================================

local bleAdvAddrExtractor = Field.new("btle.advertising_address")

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

local function safeBufferAccess(buffer, offset, length)
    if offset < 0 or length < 0 then
        return nil
    end
    if offset + length > buffer:len() then
        return nil
    end
    return buffer(offset, length)
end

local function extractBleMac(pinfo)
    local bleAddr = bleAdvAddrExtractor()
    if bleAddr then
        return bleAddr
    end
    return nil
end

local function bytesToHexString(byteArray)
    local hexStr = ""
    for i = 0, byteArray:len() - 1 do
        hexStr = hexStr .. string.format("%02x", byteArray:get_index(i))
    end
    return hexStr
end

-- =============================================================================
-- PACKET VALIDATION
-- =============================================================================

local function validatePacket(buffer)
    if buffer:len() < MIN_BUFFER_LEN then
        return false
    end
    
    if buffer(0, 1):uint() ~= OF_TYPE then
        return false
    end
    
    return true
end

-- =============================================================================
-- MAIN DISSECTOR
-- =============================================================================

function protoOfflineFinding.dissector(buffer, pinfo, tree)
    if not validatePacket(buffer) then
        return 0
    end
    
    pinfo.cols.protocol:set("OfflineFinding")
    pinfo.cols.info:set("Apple Offline Finding Advertisement")
    
    local subtree = tree:add(protoOfflineFinding, buffer(), "Apple Offline Finding Protocol")
    local offset = 0
    
    subtree:add(fieldType, buffer(offset, 1))
    offset = offset + 1
    
    local payloadLen = buffer(offset, 1):uint()
    local lenItem = subtree:add(fieldPayloadLength, buffer(offset, 1))
    if payloadLen ~= EXPECTED_PAYLOAD_LEN then
        lenItem:add_expert_info(
            PI_PROTOCOL,
            PI_NOTE,
            string.format("Payload length %d differs from standard %d", payloadLen, EXPECTED_PAYLOAD_LEN)
        )
    end
    offset = offset + 1
    
    local statusTvb = safeBufferAccess(buffer, offset, 1)
    if statusTvb then
        local statusByte = statusTvb:uint()
        local statusTree = subtree:add(fieldStatus, statusTvb)
        statusTree:add(fieldBatteryLevel, statusTvb)
        statusTree:add(fieldReservedBits, statusTvb)
        offset = offset + 1
    else
        return buffer:len()
    end
    
    local remaining = buffer:len() - offset
    
    if remaining >= PUBLIC_KEY_FRAG_LEN + 2 then
        local keyFragTvb = buffer(offset, PUBLIC_KEY_FRAG_LEN)
        subtree:add(fieldKeyFragment, keyFragTvb)
        
        local macField = extractBleMac(pinfo)
        if macField then
            local macBytes = macField.range:bytes()
            local fragBytes = keyFragTvb:bytes()
            local fullKeyBytes = macBytes .. fragBytes
            
            -- Convert ByteArray to hex string for display
            local fullKeyHex = bytesToHexString(fullKeyBytes)
            
            -- Add as a generated field with the hex string value
            local fullKeyItem = subtree:add(fieldFullPublicKey, fullKeyHex)
            fullKeyItem:set_generated()
            fullKeyItem:append_text(" [Reconstructed: MAC + Fragment]")
        end
        
        offset = offset + PUBLIC_KEY_FRAG_LEN
        
        local hintTvb = safeBufferAccess(buffer, offset, 1)
        if hintTvb then
            subtree:add(fieldKeyHint, hintTvb)
            offset = offset + 1
        end
        
        local counterTvb = safeBufferAccess(buffer, offset, 1)
        if counterTvb then
            subtree:add(fieldCounter, counterTvb)
        end
    elseif remaining > 0 then
        subtree:add(fieldKeyFragment, buffer(offset, remaining)):append_text(" [Truncated]")
    end
    
    return buffer:len()
end

-- =============================================================================
-- PROTOCOL REGISTRATION
-- =============================================================================

local dissectorTable = DissectorTable.get("btcommon.eir_ad.manufacturer_company_id")
if dissectorTable then
    dissectorTable:add(APPLE_COMPANY_ID, protoOfflineFinding)
end

print("[OfflineFinding] Apple Offline Finding Protocol dissector loaded (v1.1.1)")
print("[OfflineFinding] Copyright (C) 2025 Harry Frankl - GPL-3.0-or-later")