-- Roland Security public bootstrap. Safe to publish; contains no license, session, or private signing key.
-- Ed25519 dependency notice: third_party/THIRD_PARTY_NOTICES.md
repeat task.wait() until game:IsLoaded() and game:GetService("Players").LocalPlayer
assert(type(buffer) == "table" and type(buffer.create) == "function", "executor lacks Luau buffer support")
local __RLS_Environment = type(getgenv) == "function" and getgenv() or _G
local __RLS_LicenseKey = rawget(__RLS_Environment, "script_key")
rawset(__RLS_Environment, "script_key", nil)
rawset(__RLS_Environment, "Script", nil)
assert(type(__RLS_LicenseKey) == "string" and #__RLS_LicenseKey > 0, "script_key is required")
-- Ed25519 verify-only bundle from daily3014/rbx-cryptography (MIT).
-- Pinned commit: 6147c4702726ab59c4b31ed9304dbe8bb843f05f
local __RLS_MultiPrecision = (function()
--[=[
	Cryptography library: Multi-Precision Arithmetic (264-bit integers)

	Return type: varies by function
	Example usage:
		local MultiPrecision = require("MultiPrecision")

		--------Usage Case 1: Basic arithmetic--------
		local NumberA = MultiPrecision.Num(42)
		local NumberB = MultiPrecision.Num(17)
		local Sum = MultiPrecision.Add(NumberA, NumberB)
		local Product = MultiPrecision.Mul(NumberA, NumberB)

		--------Usage Case 2: Carry operations--------
		local LargeSum = MultiPrecision.Add(Sum, Product)
		local Normalized = MultiPrecision.Carry(LargeSum)
--]=]

--!strict
--!optimize 2
--!native

local CARRY = 88
local SIZE = 96

local MultiPrecision = {}

function MultiPrecision.CarryWeak(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(LargeNumber, 0), buffer.readf64(LargeNumber, 8),
		buffer.readf64(LargeNumber, 16), buffer.readf64(LargeNumber, 24),
		buffer.readf64(LargeNumber, 32), buffer.readf64(LargeNumber, 40),
		buffer.readf64(LargeNumber, 48), buffer.readf64(LargeNumber, 56),
		buffer.readf64(LargeNumber, 64), buffer.readf64(LargeNumber, 72),
		buffer.readf64(LargeNumber, 80)

	local Carry00 = A00 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A01 += Carry00 * 2 ^ -24
	local Carry01 = A01 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A02 += Carry01 * 2 ^ -24
	local Carry02 = A02 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A03 += Carry02 * 2 ^ -24
	local Carry03 = A03 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A04 += Carry03 * 2 ^ -24
	local Carry04 = A04 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A05 += Carry04 * 2 ^ -24
	local Carry05 = A05 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A06 += Carry05 * 2 ^ -24
	local Carry06 = A06 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A07 += Carry06 * 2 ^ -24
	local Carry07 = A07 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A08 += Carry07 * 2 ^ -24
	local Carry08 = A08 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A09 += Carry08 * 2 ^ -24
	local Carry09 = A09 + 3 * 2 ^ 75 - 3 * 2 ^ 75; A10 += Carry09 * 2 ^ -24
	local Carry10 = A10 + 3 * 2 ^ 75 - 3 * 2 ^ 75

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - Carry00)
	buffer.writef64(Buf, 8, A01 - Carry01)
	buffer.writef64(Buf, 16, A02 - Carry02)
	buffer.writef64(Buf, 24, A03 - Carry03)
	buffer.writef64(Buf, 32, A04 - Carry04)
	buffer.writef64(Buf, 40, A05 - Carry05)
	buffer.writef64(Buf, 48, A06 - Carry06)
	buffer.writef64(Buf, 56, A07 - Carry07)
	buffer.writef64(Buf, 64, A08 - Carry08)
	buffer.writef64(Buf, 72, A09 - Carry09)
	buffer.writef64(Buf, 80, A10 - Carry10)
	buffer.writef64(Buf, 88, Carry10 * 2 ^ -24)

	return Buf
end

function MultiPrecision.Carry(LargeNumber: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(LargeNumber, 0), buffer.readf64(LargeNumber, 8),
		buffer.readf64(LargeNumber, 16), buffer.readf64(LargeNumber, 24),
		buffer.readf64(LargeNumber, 32), buffer.readf64(LargeNumber, 40),
		buffer.readf64(LargeNumber, 48), buffer.readf64(LargeNumber, 56),
		buffer.readf64(LargeNumber, 64), buffer.readf64(LargeNumber, 72),
		buffer.readf64(LargeNumber, 80)

	local Low00 = A00 % 2 ^ 24; A01 += (A00 - Low00) * 2 ^ -24
	local Low01 = A01 % 2 ^ 24; A02 += (A01 - Low01) * 2 ^ -24
	local Low02 = A02 % 2 ^ 24; A03 += (A02 - Low02) * 2 ^ -24
	local Low03 = A03 % 2 ^ 24; A04 += (A03 - Low03) * 2 ^ -24
	local Low04 = A04 % 2 ^ 24; A05 += (A04 - Low04) * 2 ^ -24
	local Low05 = A05 % 2 ^ 24; A06 += (A05 - Low05) * 2 ^ -24
	local Low06 = A06 % 2 ^ 24; A07 += (A06 - Low06) * 2 ^ -24
	local Low07 = A07 % 2 ^ 24; A08 += (A07 - Low07) * 2 ^ -24
	local Low08 = A08 % 2 ^ 24; A09 += (A08 - Low08) * 2 ^ -24
	local Low09 = A09 % 2 ^ 24; A10 += (A09 - Low09) * 2 ^ -24
	local Low10 = A10 % 2 ^ 24

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, Low00)
	buffer.writef64(Buf, 8, Low01)
	buffer.writef64(Buf, 16, Low02)
	buffer.writef64(Buf, 24, Low03)
	buffer.writef64(Buf, 32, Low04)
	buffer.writef64(Buf, 40, Low05)
	buffer.writef64(Buf, 48, Low06)
	buffer.writef64(Buf, 56, Low07)
	buffer.writef64(Buf, 64, Low08)
	buffer.writef64(Buf, 72, Low09)
	buffer.writef64(Buf, 80, Low10)
	buffer.writef64(Buf, 88, (A10 - Low10) * 2 ^ -24)

	return Buf
end

function MultiPrecision.Add(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 =
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 + B00)
	buffer.writef64(Buf, 8, A01 + B01)
	buffer.writef64(Buf, 16, A02 + B02)
	buffer.writef64(Buf, 24, A03 + B03)
	buffer.writef64(Buf, 32, A04 + B04)
	buffer.writef64(Buf, 40, A05 + B05)
	buffer.writef64(Buf, 48, A06 + B06)
	buffer.writef64(Buf, 56, A07 + B07)
	buffer.writef64(Buf, 64, A08 + B08)
	buffer.writef64(Buf, 72, A09 + B09)
	buffer.writef64(Buf, 80, A10 + B10)

	return Buf
end

function MultiPrecision.Sub(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 =
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - B00)
	buffer.writef64(Buf, 8, A01 - B01)
	buffer.writef64(Buf, 16, A02 - B02)
	buffer.writef64(Buf, 24, A03 - B03)
	buffer.writef64(Buf, 32, A04 - B04)
	buffer.writef64(Buf, 40, A05 - B05)
	buffer.writef64(Buf, 48, A06 - B06)
	buffer.writef64(Buf, 56, A07 - B07)
	buffer.writef64(Buf, 64, A08 - B08)
	buffer.writef64(Buf, 72, A09 - B09)
	buffer.writef64(Buf, 80, A10 - B10)

	return Buf
end

function MultiPrecision.LMul(NumberA: buffer, NumberB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0), buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16), buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32), buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48), buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64), buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 =
		buffer.readf64(NumberB, 0), buffer.readf64(NumberB, 8),
		buffer.readf64(NumberB, 16), buffer.readf64(NumberB, 24),
		buffer.readf64(NumberB, 32), buffer.readf64(NumberB, 40),
		buffer.readf64(NumberB, 48), buffer.readf64(NumberB, 56),
		buffer.readf64(NumberB, 64), buffer.readf64(NumberB, 72),
		buffer.readf64(NumberB, 80)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 * B00)
	buffer.writef64(Buf, 8, A01 * B00 + A00 * B01)
	buffer.writef64(Buf, 16, A02 * B00 + A01 * B01 + A00 * B02)
	buffer.writef64(Buf, 24, A03 * B00 + A02 * B01 + A01 * B02 + A00 * B03)
	buffer.writef64(Buf, 32, A04 * B00 + A03 * B01 + A02 * B02 + A01 * B03 + A00 * B04)
	buffer.writef64(Buf, 40, A05 * B00 + A04 * B01 + A03 * B02 + A02 * B03 + A01 * B04 + A00 * B05)
	buffer.writef64(Buf, 48, A06 * B00 + A05 * B01 + A04 * B02 + A03 * B03 + A02 * B04 + A01 * B05 + A00 * B06)
	buffer.writef64(Buf, 56, A07 * B00 + A06 * B01 + A05 * B02 + A04 * B03 + A03 * B04 + A02 * B05 + A01 * B06 + A00 * B07)
	buffer.writef64(Buf, 64, A08 * B00 + A07 * B01 + A06 * B02 + A05 * B03 + A04 * B04 + A03 * B05 + A02 * B06 + A01 * B07 + A00 * B08)
	buffer.writef64(Buf, 72, A09 * B00 + A08 * B01 + A07 * B02 + A06 * B03 + A05 * B04 + A04 * B05 + A03 * B06 + A02 * B07 + A01 * B08 + A00 * B09)
	buffer.writef64(Buf, 80, A10 * B00 + A09 * B01 + A08 * B02 + A07 * B03 + A06 * B04 + A05 * B05 + A04 * B06 + A03 * B07 + A02 * B08 + A01 * B09 + A00 * B10)

	return MultiPrecision.Carry(Buf, Buf)
end

function MultiPrecision.Mul(NumberA: buffer, NumberB: buffer, LowStorage: buffer?, HighStorage: buffer?): (buffer, buffer)
	local LowResult = MultiPrecision.LMul(NumberA, NumberB, LowStorage)
	local Overflow = buffer.readf64(LowResult, CARRY)

	local A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 8), buffer.readf64(NumberA, 16),
		buffer.readf64(NumberA, 24), buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40), buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56), buffer.readf64(NumberA, 64),
		buffer.readf64(NumberA, 72), buffer.readf64(NumberA, 80)

	local B01, B02, B03, B04, B05, B06, B07, B08, B09, B10 =
		buffer.readf64(NumberB, 8), buffer.readf64(NumberB, 16),
		buffer.readf64(NumberB, 24), buffer.readf64(NumberB, 32),
		buffer.readf64(NumberB, 40), buffer.readf64(NumberB, 48),
		buffer.readf64(NumberB, 56), buffer.readf64(NumberB, 64),
		buffer.readf64(NumberB, 72), buffer.readf64(NumberB, 80)

	local Buf = HighStorage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, Overflow + A10 * B01 + A09 * B02 + A08 * B03 + A07 * B04 + A06 * B05 + A05 * B06 + A04 * B07 + A03 * B08 + A02 * B09 + A01 * B10)
	buffer.writef64(Buf, 8, A10 * B02 + A09 * B03 + A08 * B04 + A07 * B05 + A06 * B06 + A05 * B07 + A04 * B08 + A03 * B09 + A02 * B10)
	buffer.writef64(Buf, 16, A10 * B03 + A09 * B04 + A08 * B05 + A07 * B06 + A06 * B07 + A05 * B08 + A04 * B09 + A03 * B10)
	buffer.writef64(Buf, 24, A10 * B04 + A09 * B05 + A08 * B06 + A07 * B07 + A06 * B08 + A05 * B09 + A04 * B10)
	buffer.writef64(Buf, 32, A10 * B05 + A09 * B06 + A08 * B07 + A07 * B08 + A06 * B09 + A05 * B10)
	buffer.writef64(Buf, 40, A10 * B06 + A09 * B07 + A08 * B08 + A07 * B09 + A06 * B10)
	buffer.writef64(Buf, 48, A10 * B07 + A09 * B08 + A08 * B09 + A07 * B10)
	buffer.writef64(Buf, 56, A10 * B08 + A09 * B09 + A08 * B10)
	buffer.writef64(Buf, 64, A10 * B09 + A09 * B10)
	buffer.writef64(Buf, 72, A10 * B10)
	buffer.writef64(Buf, 80, 0)

	return LowResult, MultiPrecision.Carry(Buf, Buf)
end

function MultiPrecision.DWAdd(NumberA0: buffer, NumberA1: buffer, NumberB0: buffer, NumberB1: buffer, LowStorage: buffer?, HighStorage: buffer?): (buffer, buffer, number)
	local LowSum = MultiPrecision.Carry(MultiPrecision.Add(NumberA0, NumberB0, LowStorage), LowStorage)
	local CarryOut = buffer.readf64(LowSum, CARRY)

	local HighSum = MultiPrecision.Add(NumberA1, NumberB1, HighStorage)
	buffer.writef64(HighSum, 0, buffer.readf64(HighSum, 0) + CarryOut)
	local Carried = MultiPrecision.Carry(HighSum, HighSum)

	return LowSum, Carried, buffer.readf64(Carried, CARRY)
end

function MultiPrecision.Half(NumberA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0),
		buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16),
		buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64),
		buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 * 0.5 + A01 * 2 ^ 23)
	buffer.writef64(Buf, 8, A02 * 2 ^ 23)
	buffer.writef64(Buf, 16, A03 * 2 ^ 23)
	buffer.writef64(Buf, 24, A04 * 2 ^ 23)
	buffer.writef64(Buf, 32, A05 * 2 ^ 23)
	buffer.writef64(Buf, 40, A06 * 2 ^ 23)
	buffer.writef64(Buf, 48, A07 * 2 ^ 23)
	buffer.writef64(Buf, 56, A08 * 2 ^ 23)
	buffer.writef64(Buf, 64, A09 * 2 ^ 23)
	buffer.writef64(Buf, 72, A10 * 2 ^ 23)
	buffer.writef64(Buf, 80, 0)

	return MultiPrecision.CarryWeak(Buf, Buf)
end

function MultiPrecision.Third(NumberA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 =
		buffer.readf64(NumberA, 0),
		buffer.readf64(NumberA, 8),
		buffer.readf64(NumberA, 16),
		buffer.readf64(NumberA, 24),
		buffer.readf64(NumberA, 32),
		buffer.readf64(NumberA, 40),
		buffer.readf64(NumberA, 48),
		buffer.readf64(NumberA, 56),
		buffer.readf64(NumberA, 64),
		buffer.readf64(NumberA, 72),
		buffer.readf64(NumberA, 80)

	local Division00 = A00 * 0xaaaaaa
	local Division01 = A01 * 0xaaaaaa + Division00
	local Division02 = A02 * 0xaaaaaa + Division01
	local Division03 = A03 * 0xaaaaaa + Division02
	local Division04 = A04 * 0xaaaaaa + Division03
	local Division05 = A05 * 0xaaaaaa + Division04
	local Division06 = A06 * 0xaaaaaa + Division05
	local Division07 = A07 * 0xaaaaaa + Division06
	local Division08 = A08 * 0xaaaaaa + Division07
	local Division09 = A09 * 0xaaaaaa + Division08
	local Division10 = A10 * 0xaaaaaa + Division09

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 + Division00)
	buffer.writef64(Buf, 8, A01 + Division01)
	buffer.writef64(Buf, 16, A02 + Division02)
	buffer.writef64(Buf, 24, A03 + Division03)
	buffer.writef64(Buf, 32, A04 + Division04)
	buffer.writef64(Buf, 40, A05 + Division05)
	buffer.writef64(Buf, 48, A06 + Division06)
	buffer.writef64(Buf, 56, A07 + Division07)
	buffer.writef64(Buf, 64, A08 + Division08)
	buffer.writef64(Buf, 72, A09 + Division09)
	buffer.writef64(Buf, 80, A10 + Division10)

	return MultiPrecision.CarryWeak(Buf, Buf)
end

function MultiPrecision.Mod2(NumberA: buffer): number
	return buffer.readf64(NumberA, 0) % 2
end

function MultiPrecision.Mod3(NumberA: buffer): number
	return (
		buffer.readf64(NumberA, 0) +
			buffer.readf64(NumberA, 8) +
			buffer.readf64(NumberA, 16) +
			buffer.readf64(NumberA, 24) +
			buffer.readf64(NumberA, 32) +
			buffer.readf64(NumberA, 40) +
			buffer.readf64(NumberA, 48) +
			buffer.readf64(NumberA, 56) +
			buffer.readf64(NumberA, 64) +
			buffer.readf64(NumberA, 72) +
			buffer.readf64(NumberA, 80)
	) % 3
end

function MultiPrecision.Approx(NumberA: buffer): number
	return buffer.readf64(NumberA, 0)
		+ buffer.readf64(NumberA, 8) * 2 ^ 24
		+ buffer.readf64(NumberA, 16) * 2 ^ 48
		+ buffer.readf64(NumberA, 24) * 2 ^ 72
		+ buffer.readf64(NumberA, 32) * 2 ^ 96
		+ buffer.readf64(NumberA, 40) * 2 ^ 120
		+ buffer.readf64(NumberA, 48) * 2 ^ 144
		+ buffer.readf64(NumberA, 56) * 2 ^ 168
		+ buffer.readf64(NumberA, 64) * 2 ^ 192
		+ buffer.readf64(NumberA, 72) * 2 ^ 216
		+ buffer.readf64(NumberA, 80) * 2 ^ 240
end

function MultiPrecision.Cmp(NumberA: buffer, NumberB: buffer): number
	return MultiPrecision.Approx(MultiPrecision.Sub(NumberA, NumberB))
end

function MultiPrecision.Num(RegularNumber: number): buffer
	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, RegularNumber)

	return Buf
end

return MultiPrecision
end)()

local __RLS_FieldQuadratic = (function()
--[=[
	Cryptography library: Field Quadratic (Curve25519 Scalar Field)

	Return type: varies by function
	Example usage:
		local FieldQuadratic = require("FieldQuadratic")

		--------Usage Case 1: Basic scalar arithmetic--------
		local ScalarA = FieldQuadratic.Decode(SomeBytes)
		local ScalarB = FieldQuadratic.Decode(OtherBytes)
		local Sum = FieldQuadratic.Add(ScalarA, ScalarB)
		local Product = FieldQuadratic.Mul(ScalarA, ScalarB)

		--------Usage Case 2: Convert to bits for scalar multiplication--------
		local ScalarBits = FieldQuadratic.Bits(ScalarA)
		local EncodedResult = FieldQuadratic.Encode(Product)
--]=]

--!strict
--!optimize 2
--!native

local MultiPrecision = __RLS_MultiPrecision
local CONSTANT_ZERO = MultiPrecision.Num(0)

local OUTPUT_BUFFER = buffer.create(8192)
local RULE_BUFFER = buffer.create(8192)
local DECODE_WIDE_LOW = buffer.create(96)
local DECODE_WIDE_HIGH = buffer.create(96)
local DECODE_BUFFER = buffer.create(96)
local CLAMPED_BUFFER = buffer.create(32)

local FIELD_ORDER_BYTES = buffer.create(32) do
	local Bytes = {
		0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
	}
	for Index = 1, 32 do
		buffer.writeu8(FIELD_ORDER_BYTES, Index - 1, Bytes[Index])
	end
end

local FIELD_ORDER = buffer.create(96) do
	local ByteIndex = 0

	for LimbIndex = 0, 9 do
		local Value = buffer.readu8(FIELD_ORDER_BYTES, ByteIndex)
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 1) * 256
			+ buffer.readu8(FIELD_ORDER_BYTES, ByteIndex + 2) * 65536

		buffer.writef64(FIELD_ORDER, LimbIndex * 8, Value)
		ByteIndex += 3
	end

	local LastValue = buffer.readu8(FIELD_ORDER_BYTES, 30)
		+ buffer.readu8(FIELD_ORDER_BYTES, 31) * 256
	buffer.writef64(FIELD_ORDER, 10 * 8, LastValue)
end

local MONTGOMERY_T0 = buffer.create(96) do
	local Values = {
		05537307, 01942290, 16765621, 16628356, 10618610,
		07072433, 03735459, 01369940, 15276086, 13038191,
		13409718
	}
	for Index = 1, 11 do
		buffer.writef64(MONTGOMERY_T0, (Index - 1) * 8, Values[Index])
	end
end

local MONTGOMERY_T1 = buffer.create(96) do
	local Values = {
		11711996, 01747860, 08326961, 03814718, 01859974,
		13327461, 16105061, 07590423, 04050668, 08138906,
		00000283
	}
	for Index = 1, 11 do
		buffer.writef64(MONTGOMERY_T1, (Index - 1) * 8, Values[Index])
	end
end

local DIVIDE_8 = buffer.create(96) do
	local Values = {
		5110253, 3039345, 2503500, 11779568, 15416472,
		16766550, 16777215, 16777215, 16777215, 16777215,
		4095
	}
	for Index = 1, 11 do
		buffer.writef64(DIVIDE_8, (Index - 1) * 8, Values[Index])
	end
end

local function Reduce(LargeNumber: buffer): buffer
	local Difference = MultiPrecision.Sub(LargeNumber, FIELD_ORDER)

	if MultiPrecision.Approx(Difference) < 0 then
		return MultiPrecision.Carry(LargeNumber)
	end

	return MultiPrecision.Carry(Difference)
end

local function Demontgomery(MontgomeryScalar: buffer): buffer
	local ReductionLow, ReductionHigh = MultiPrecision.Mul(MultiPrecision.LMul(MontgomeryScalar, MONTGOMERY_T0), FIELD_ORDER)
	local _, ResultHigh = MultiPrecision.DWAdd(MontgomeryScalar, CONSTANT_ZERO, ReductionLow, ReductionHigh)

	return Reduce(ResultHigh)
end

local function RebaseLE(InputBuffer: buffer, InputLength: number, FromBase: number, ToBase: number): (buffer, number)
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for Index = 0, InputLength - 1 do
		Accumulator += buffer.readf64(InputBuffer, Index * 8) * Multiplier
		Multiplier *= FromBase
		while Multiplier >= ToBase do
			local Remainder = Accumulator % ToBase
			Accumulator = (Accumulator - Remainder) / ToBase
			Multiplier /= ToBase
			buffer.writef64(OUTPUT_BUFFER, OutputLength * 8, Remainder)
			OutputLength += 1
		end
	end

	if Multiplier > 0 then
		buffer.writef64(OUTPUT_BUFFER, OutputLength * 8, Accumulator)
		OutputLength += 1
	end

	return OUTPUT_BUFFER, OutputLength
end

local FieldQuadratic = {}

function FieldQuadratic.IsValidScalar(ScalarBytes: buffer): boolean
	local FieldOrder = FIELD_ORDER_BYTES
	local Borrow = 0

	for Index = 0, 31 do
		local ScalarByte = buffer.readu8(ScalarBytes, Index)
		local OrderByte = buffer.readu8(FieldOrder, Index)
		local Diff = ScalarByte - OrderByte - Borrow
		Borrow = 1 - bit32.rshift(Diff + 256, 8)
	end

	return Borrow == 1
end

function FieldQuadratic.Montgomery(RegularScalar: buffer): buffer
	return FieldQuadratic.Mul(RegularScalar, MONTGOMERY_T1)
end

function FieldQuadratic.Add(ScalarA: buffer, ScalarB: buffer): buffer
	return Reduce(MultiPrecision.Add(ScalarA, ScalarB))
end

function FieldQuadratic.Neg(ScalarA: buffer): buffer
	return Reduce(MultiPrecision.Sub(FIELD_ORDER, ScalarA))
end

function FieldQuadratic.Sub(ScalarA: buffer, ScalarB: buffer): buffer
	return FieldQuadratic.Add(ScalarA, FieldQuadratic.Neg(ScalarB))
end

function FieldQuadratic.Mul(ScalarA: buffer, ScalarB: buffer): buffer
	local ProductLow, ProductHigh = MultiPrecision.Mul(ScalarA, ScalarB)
	local ReductionLow, ReductionHigh = MultiPrecision.Mul(MultiPrecision.LMul(ProductLow, MONTGOMERY_T0), FIELD_ORDER)
	local _, ResultHigh = MultiPrecision.DWAdd(ProductLow, ProductHigh, ReductionLow, ReductionHigh)

	return Reduce(ResultHigh)
end

function FieldQuadratic.Encode(MontgomeryScalar: buffer): buffer
	local DemontResult = Demontgomery(MontgomeryScalar)
	local EncodedBuffer = buffer.create(32)
	local ByteIndex = 0
	for LimbIndex = 0, 9 do
		local Value = buffer.readf64(DemontResult, LimbIndex * 8)
		buffer.writeu8(EncodedBuffer, ByteIndex, Value % 256)
		Value = Value // 256
		buffer.writeu8(EncodedBuffer, ByteIndex + 1, Value % 256)
		Value = Value // 256
		buffer.writeu8(EncodedBuffer, ByteIndex + 2, Value % 256)
		ByteIndex += 3
	end

	local LastValue = buffer.readf64(DemontResult, 10 * 8)
	buffer.writeu8(EncodedBuffer, 30, LastValue % 256)
	LastValue = LastValue // 256
	buffer.writeu8(EncodedBuffer, 31, LastValue % 256)

	return EncodedBuffer
end

function FieldQuadratic.Decode(EncodedBuffer: buffer): buffer
	local DecodedBuffer = DECODE_BUFFER
	local ByteIndex = 0

	for LimbIndex = 0, 9 do
		local Value = buffer.readu8(EncodedBuffer, ByteIndex)
			+ buffer.readu8(EncodedBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(EncodedBuffer, ByteIndex + 2) * 65536

		buffer.writef64(DecodedBuffer, LimbIndex * 8, Value)
		ByteIndex += 3
	end

	local LastValue = buffer.readu8(EncodedBuffer, 30)
		+ buffer.readu8(EncodedBuffer, 31) * 256
	buffer.writef64(DecodedBuffer, 10 * 8, LastValue)

	return FieldQuadratic.Montgomery(DecodedBuffer)
end

function FieldQuadratic.DecodeWide(WideBuffer: buffer): buffer
	local LowPart = DECODE_WIDE_LOW
	local HighPart = DECODE_WIDE_HIGH

	for LimbIndex = 0, 10 do
		local ByteIndex = LimbIndex * 3
		local Value = buffer.readu8(WideBuffer, ByteIndex)
			+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		buffer.writef64(LowPart, LimbIndex * 8, Value)
	end

	for LimbIndex = 0, 9 do
		local ByteIndex = 33 + LimbIndex * 3
		local Value = buffer.readu8(WideBuffer, ByteIndex)
			+ buffer.readu8(WideBuffer, ByteIndex + 1) * 256
			+ buffer.readu8(WideBuffer, ByteIndex + 2) * 65536
		buffer.writef64(HighPart, LimbIndex * 8, Value)
	end
	buffer.writef64(HighPart, 10 * 8, buffer.readu8(WideBuffer, 63))

	local MontLow = FieldQuadratic.Montgomery(LowPart)
	local MontHigh = FieldQuadratic.Montgomery(HighPart)
	local MontMontHigh = FieldQuadratic.Montgomery(MontHigh)

	return FieldQuadratic.Add(MontLow, MontMontHigh)
end

function FieldQuadratic.DecodeClamped(ClampedBuffer: buffer): buffer
	local ClampedCopy = CLAMPED_BUFFER
	buffer.copy(ClampedCopy, 0, ClampedBuffer, 0, 32)

	local FirstByte = buffer.readu8(ClampedCopy, 0)
	buffer.writeu8(ClampedCopy, 0, bit32.band(FirstByte, 0xF8))

	local LastByte = buffer.readu8(ClampedCopy, 31)
	buffer.writeu8(ClampedCopy, 31, bit32.bor(bit32.band(LastByte, 0x7F), 0x40))

	return FieldQuadratic.Decode(ClampedCopy)
end

function FieldQuadratic.Eighth(MontgomeryScalar: buffer): buffer
	return FieldQuadratic.Mul(MontgomeryScalar, DIVIDE_8)
end

function FieldQuadratic.Bits(MontgomeryScalar: buffer): (buffer, number)
	local DemontResult = Demontgomery(MontgomeryScalar)
	local BitOutput, BitCount = RebaseLE(DemontResult, 11, 2 ^ 24, 2)

	if BitCount > 253 then
		BitCount = 253
	end

	return BitOutput, BitCount
end

function FieldQuadratic.MakeRuleset(ScalarA: buffer, ScalarB: buffer): (buffer, number, buffer, number)
	local DTable = Demontgomery(ScalarA)
	local ETable = Demontgomery(ScalarB)
	local FTable = MultiPrecision.Sub(DTable, ETable)

	local DMod2 = MultiPrecision.Mod2(DTable)
	local EMod2 = MultiPrecision.Mod2(ETable)

	local DMod3 = MultiPrecision.Mod3(DTable)
	local EMod3 = MultiPrecision.Mod3(ETable)

	local EFloat = MultiPrecision.Approx(ETable)
	local FFloat = MultiPrecision.Approx(FTable)

	local Mod3Lut = {[0] = 0, 2, 1}

	local RuleBuffer = RULE_BUFFER
	local RuleCount = 0

	while FFloat ~= 0 do
		local Rule = -1

		if FFloat < 0 then
			Rule = 0
			DTable, ETable = ETable, DTable
			DMod2, EMod2 = EMod2, DMod2
			DMod3, EMod3 = EMod3, DMod3
			EFloat = MultiPrecision.Approx(ETable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = -FFloat
		elseif 4 * FFloat < EFloat and DMod3 == Mod3Lut[EMod3] then
			Rule = 1
			DTable, ETable = MultiPrecision.Third(MultiPrecision.Add(DTable, FTable)), MultiPrecision.Third(MultiPrecision.Sub(ETable, FTable)) :: buffer
			DMod2, EMod2 = EMod2, DMod2
			DMod3, EMod3 = MultiPrecision.Mod3(DTable), MultiPrecision.Mod3(ETable)
			EFloat = MultiPrecision.Approx(ETable)
		elseif 4 * FFloat < EFloat and DMod2 == EMod2 and DMod3 == EMod3 then
			Rule = 2
			DTable = MultiPrecision.Half(FTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[(DMod3 - EMod3) % 3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif FFloat < 3 * EFloat then
			Rule = 3
			DTable = MultiPrecision.CarryWeak(FTable)
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = (DMod3 - EMod3) % 3
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod2 == EMod2 then
			Rule = 2
			DTable = MultiPrecision.Half(FTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[(DMod3 - EMod3) % 3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod2 == 0 then
			Rule = 5
			DTable = MultiPrecision.Half(DTable)
			DMod2 = MultiPrecision.Mod2(DTable)
			DMod3 = Mod3Lut[DMod3]
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == 0 then
			Rule = 6
			DTable = MultiPrecision.CarryWeak(MultiPrecision.Sub(MultiPrecision.Third(DTable), ETable))
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == Mod3Lut[EMod3] then
			Rule = 7
			DTable = MultiPrecision.Third(MultiPrecision.Sub(FTable, ETable))
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		elseif DMod3 == EMod3 then
			Rule = 8
			DTable = MultiPrecision.Third(FTable)
			DMod2 = (DMod2 - EMod2) % 2
			DMod3 = MultiPrecision.Mod3(DTable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		else
			Rule = 9
			ETable = MultiPrecision.Half(ETable)
			EMod2 = MultiPrecision.Mod2(ETable)
			EMod3 = Mod3Lut[EMod3]
			EFloat = MultiPrecision.Approx(ETable)
			FTable = MultiPrecision.Sub(DTable, ETable)
			FFloat = MultiPrecision.Approx(FTable)
		end

		buffer.writef64(RuleBuffer, RuleCount * 8, Rule)
		RuleCount += 1
	end

	local FinalBits, FinalBitCount = RebaseLE(DTable, 11, 2 ^ 24, 2)
	while FinalBitCount > 0 and buffer.readf64(FinalBits, (FinalBitCount - 1) * 8) == 0 do
		FinalBitCount -= 1
	end

	return FinalBits, FinalBitCount, RuleBuffer, RuleCount
end

return FieldQuadratic
end)()

local __RLS_FieldPrime = (function()
--[=[
	Cryptography library: Field Prime (Curve25519 Base Field)

	Return type: varies by function
	Example usage:
		local FieldPrime = require("FieldPrime")

		--------Usage Case 1: Basic arithmetic--------
		local ElementA = FieldPrime.Num(42)
		local ElementB = FieldPrime.Num(17)
		local Sum = FieldPrime.Add(ElementA, ElementB)
		local Product = FieldPrime.Mul(ElementA, ElementB)

		--------Usage Case 2: Encoding/decoding--------
		local Encoded = FieldPrime.Encode(ElementA)
		local Decoded = FieldPrime.Decode(Encoded)
--]=]

--!strict
--!optimize 2
--!native

local SIZE = 104
local COMPOUND_V = (19 / 2 ^ 255)
local SQUARES = buffer.create(SIZE) do
	local Tbl = {
		0958640 * 2 ^ 0,
		0826664 * 2 ^ 22,
		1613251 * 2 ^ 43,
		1041528 * 2 ^ 64,
		0013673 * 2 ^ 85,
		0387171 * 2 ^ 107,
		1824679 * 2 ^ 128,
		0313839 * 2 ^ 149,
		0709440 * 2 ^ 170,
		0122635 * 2 ^ 192,
		0262782 * 2 ^ 213,
		0712905 * 2 ^ 234,
	}

	for Index = 1, 12 do
		buffer.writef64(SQUARES, (Index - 1) * 8, Tbl[Index])
	end
end

local FieldPrime = {}

function FieldPrime.Num(Number: number): buffer
	local Buf = buffer.create(SIZE)
	buffer.writef64(Buf, 0, Number)

	return Buf
end

function FieldPrime.Neg(ElementA: buffer): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, -A00)
	buffer.writef64(Buf, 8, -A01)
	buffer.writef64(Buf, 16, -A02)
	buffer.writef64(Buf, 24, -A03)
	buffer.writef64(Buf, 32, -A04)
	buffer.writef64(Buf, 40, -A05)
	buffer.writef64(Buf, 48, -A06)
	buffer.writef64(Buf, 56, -A07)
	buffer.writef64(Buf, 64, -A08)
	buffer.writef64(Buf, 72, -A09)
	buffer.writef64(Buf, 80, -A10)
	buffer.writef64(Buf, 88, -A11)

	return Buf
end

function FieldPrime.Add(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 + B00)
	buffer.writef64(Buf, 8, A01 + B01)
	buffer.writef64(Buf, 16, A02 + B02)
	buffer.writef64(Buf, 24, A03 + B03)
	buffer.writef64(Buf, 32, A04 + B04)
	buffer.writef64(Buf, 40, A05 + B05)
	buffer.writef64(Buf, 48, A06 + B06)
	buffer.writef64(Buf, 56, A07 + B07)
	buffer.writef64(Buf, 64, A08 + B08)
	buffer.writef64(Buf, 72, A09 + B09)
	buffer.writef64(Buf, 80, A10 + B10)
	buffer.writef64(Buf, 88, A11 + B11)

	return Buf
end

function FieldPrime.Sub(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - B00)
	buffer.writef64(Buf, 8, A01 - B01)
	buffer.writef64(Buf, 16, A02 - B02)
	buffer.writef64(Buf, 24, A03 - B03)
	buffer.writef64(Buf, 32, A04 - B04)
	buffer.writef64(Buf, 40, A05 - B05)
	buffer.writef64(Buf, 48, A06 - B06)
	buffer.writef64(Buf, 56, A07 - B07)
	buffer.writef64(Buf, 64, A08 - B08)
	buffer.writef64(Buf, 72, A09 - B09)
	buffer.writef64(Buf, 80, A10 - B10)
	buffer.writef64(Buf, 88, A11 - B11)

	return Buf
end

function FieldPrime.Carry(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 += 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 += C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 += C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 += C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 += C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 += C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 += C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 += C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 += C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 += C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - C00 + 19 / 2 ^ 255 * C11)
	buffer.writef64(Buf, 8, A01 - C01)
	buffer.writef64(Buf, 16, A02 - C02)
	buffer.writef64(Buf, 24, A03 - C03)
	buffer.writef64(Buf, 32, A04 - C04)
	buffer.writef64(Buf, 40, A05 - C05)
	buffer.writef64(Buf, 48, A06 - C06)
	buffer.writef64(Buf, 56, A07 - C07)
	buffer.writef64(Buf, 64, A08 - C08)
	buffer.writef64(Buf, 72, A09 - C09)
	buffer.writef64(Buf, 80, A10 - C10)
	buffer.writef64(Buf, 88, A11 - C11)

	return Buf
end

function FieldPrime.Canonicalize(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	C00 = A00 % 2 ^ 22
	A01 += A00 - C00
	C01 = A01 % 2 ^ 43
	A02 += A01 - C01
	C02 = A02 % 2 ^ 64
	A03 += A02 - C02
	C03 = A03 % 2 ^ 85
	A04 += A03 - C03
	C04 = A04 % 2 ^ 107
	A05 += A04 - C04
	C05 = A05 % 2 ^ 128
	A06 += A05 - C05
	C06 = A06 % 2 ^ 149
	A07 += A06 - C06
	C07 = A07 % 2 ^ 170
	A08 += A07 - C07
	C08 = A08 % 2 ^ 192
	A09 += A08 - C08
	C09 = A09 % 2 ^ 213
	A10 += A09 - C09
	C10 = A10 % 2 ^ 234
	A11 += A10 - C10
	C11 = A11 % 2 ^ 255
	C00 += 19 / 2 ^ 255 * (A11 - C11)

	local Buf = Storage or buffer.create(SIZE)
	if C11 / 2 ^ 234 == 2 ^ 21 - 1
		and C10 / 2 ^ 213 == 2 ^ 21 - 1
		and C09 / 2 ^ 192 == 2 ^ 21 - 1
		and C08 / 2 ^ 170 == 2 ^ 22 - 1
		and C07 / 2 ^ 149 == 2 ^ 21 - 1
		and C06 / 2 ^ 128 == 2 ^ 21 - 1
		and C05 / 2 ^ 107 == 2 ^ 21 - 1
		and C04 / 2 ^ 85 == 2 ^ 22 - 1
		and C03 / 2 ^ 64 == 2 ^ 21 - 1
		and C02 / 2 ^ 43 == 2 ^ 21 - 1
		and C01 / 2 ^ 22 == 2 ^ 21 - 1
		and C00 >= 2 ^ 22 - 19
	then
		buffer.writef64(Buf, 0, 19 - 2 ^ 22 + C00)
		for Index = 8, 88, 8 do
			buffer.writef64(Buf, Index, 0)
		end
	else
		buffer.writef64(Buf, 0, C00)
		buffer.writef64(Buf, 8, C01)
		buffer.writef64(Buf, 16, C02)
		buffer.writef64(Buf, 24, C03)
		buffer.writef64(Buf, 32, C04)
		buffer.writef64(Buf, 40, C05)
		buffer.writef64(Buf, 48, C06)
		buffer.writef64(Buf, 56, C07)
		buffer.writef64(Buf, 64, C08)
		buffer.writef64(Buf, 72, C09)
		buffer.writef64(Buf, 80, C10)
		buffer.writef64(Buf, 88, C11)
	end

	return Buf
end

function FieldPrime.Eq(ElementA: buffer, ElementB: buffer): boolean
	local Difference = FieldPrime.Canonicalize(FieldPrime.Sub(ElementA, ElementB))
	local DifferenceAccumulator = 0
	for LimbIndex = 0, 88, 8 do
		local LimbLow = buffer.readu32(Difference, LimbIndex)
		local LimbHigh = buffer.readu32(Difference, LimbIndex + 4)
		DifferenceAccumulator = bit32.bor(DifferenceAccumulator, LimbLow, LimbHigh)
	end

	return DifferenceAccumulator == 0
end

local A00: number, A01: number, A02: number, A03: number, A04: number, A05: number, A06: number,
A07: number, A08: number, A09: number, A10: number, A11: number
local B00: number, B01: number, B02: number, B03: number, B04: number, B05: number, B06: number,
B07: number, B08: number, B09: number, B10: number, B11: number

function FieldPrime.Mul(ElementA: buffer, ElementB: buffer, Storage: buffer?): buffer
	local CompoundV = COMPOUND_V
	A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11 =
		buffer.readf64(ElementB, 0), buffer.readf64(ElementB, 8),
		buffer.readf64(ElementB, 16), buffer.readf64(ElementB, 24),
		buffer.readf64(ElementB, 32), buffer.readf64(ElementB, 40),
		buffer.readf64(ElementB, 48), buffer.readf64(ElementB, 56),
		buffer.readf64(ElementB, 64), buffer.readf64(ElementB, 72),
		buffer.readf64(ElementB, 80), buffer.readf64(ElementB, 88)

	local T00: number, T01: number, T02: number, T03: number, T04: number, T05: number, T06: number,
	T07: number, T08: number, T09: number, T10: number, T11: number =
		A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11

	local U00: number, U01: number, U02: number, U03: number, U04: number, U05: number, U06: number,
	U07: number, U08: number, U09: number, U10: number, U11: number =
		B00, B01, B02, B03, B04, B05, B06, B07, B08, B09, B10, B11

	local C00 = T11 * U01
		+ T10 * U02
		+ T09 * U03
		+ T08 * U04
		+ T07 * U05
		+ T06 * U06
		+ T05 * U07
		+ T04 * U08
		+ T03 * U09
		+ T02 * U10
		+ T01 * U11

	local C01 = T11 * U02
		+ T10 * U03
		+ T09 * U04
		+ T08 * U05
		+ T07 * U06
		+ T06 * U07
		+ T05 * U08
		+ T04 * U09
		+ T03 * U10
		+ T02 * U11

	local C02 = T11 * U03
		+ T10 * U04
		+ T09 * U05
		+ T08 * U06
		+ T07 * U07
		+ T06 * U08
		+ T05 * U09
		+ T04 * U10
		+ T03 * U11

	local C03 = T11 * U04
		+ T10 * U05
		+ T09 * U06
		+ T08 * U07
		+ T07 * U08
		+ T06 * U09
		+ T05 * U10
		+ T04 * U11

	local C04 = T11 * U05
		+ T10 * U06
		+ T09 * U07
		+ T08 * U08
		+ T07 * U09
		+ T06 * U10
		+ T05 * U11

	local C05 = T11 * U06
		+ T10 * U07
		+ T09 * U08
		+ T08 * U09
		+ T07 * U10
		+ T06 * U11

	local C06 = T11 * U07
		+ T10 * U08
		+ T09 * U09
		+ T08 * U10
		+ T07 * U11

	local C07 = T11 * U08
		+ T10 * U09
		+ T09 * U10
		+ T08 * U11

	local C08 = T11 * U09
		+ T10 * U10
		+ T09 * U11

	local C09 = T11 * U10 + T10 * U11
	local C10 = T11 * U11

	C00 *= CompoundV
	C00 += T00 * U00

	C01 *= CompoundV
	C01 += T01 * U00
		+ T00 * U01

	C02 *= CompoundV
	C02 += T02 * U00
		+ T01 * U01
		+ T00 * U02

	C03 *= CompoundV
	C03 += T03 * U00
		+ T02 * U01
		+ T01 * U02
		+ T00 * U03

	C04 *= CompoundV
	C04 += T04 * U00
		+ T03 * U01
		+ T02 * U02
		+ T01 * U03
		+ T00 * U04

	C05 *= CompoundV
	C05 += T05 * U00
		+ T04 * U01
		+ T03 * U02
		+ T02 * U03
		+ T01 * U04
		+ T00 * U05

	C06 *= CompoundV
	C06 += T06 * U00
		+ T05 * U01
		+ T04 * U02
		+ T03 * U03
		+ T02 * U04
		+ T01 * U05
		+ T00 * U06

	C07 *= CompoundV
	C07 += T07 * U00
		+ T06 * U01
		+ T05 * U02
		+ T04 * U03
		+ T03 * U04
		+ T02 * U05
		+ T01 * U06
		+ T00 * U07

	C08 *= CompoundV
	C08 += T08 * U00
		+ T07 * U01
		+ T06 * U02
		+ T05 * U03
		+ T04 * U04
		+ T03 * U05
		+ T02 * U06
		+ T01 * U07
		+ T00 * U08

	C09 *= CompoundV
	C09 += T09 * U00
		+ T08 * U01
		+ T07 * U02
		+ T06 * U03
		+ T05 * U04
		+ T04 * U05
		+ T03 * U06
		+ T02 * U07
		+ T01 * U08
		+ T00 * U09

	C10 *= CompoundV
	C10 += T10 * U00
		+ T09 * U01
		+ T08 * U02
		+ T07 * U03
		+ T06 * U04
		+ T05 * U05
		+ T04 * U06
		+ T03 * U07
		+ T02 * U08
		+ T01 * U09
		+ T00 * U10

	local C11 = T11 * U00
		+ T10 * U01
		+ T09 * U02
		+ T08 * U03
		+ T07 * U04
		+ T06 * U05
		+ T05 * U06
		+ T04 * U07
		+ T03 * U08
		+ T02 * U09
		+ T01 * U10
		+ T00 * U11

	T10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 += T10
	T11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	C00 += CompoundV * T11

	T00 = C00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	C01 += T00
	T01 = C01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	C02 += T01
	T02 = C02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	C03 += T02
	T03 = C03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	C04 += T03
	T04 = C04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	C05 += T04
	T05 = C05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	C06 += T05
	T06 = C06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	C07 += T06
	T07 = C07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	C08 += T07
	T08 = C08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	C09 += T08
	T09 = C09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	C10 = C10 - T10 + T09
	T10 = C10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	C11 = C11 - T11 + T10

	T11 = C11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, C00 - T00 + CompoundV * T11)
	buffer.writef64(Buf, 8, C01 - T01)
	buffer.writef64(Buf, 16, C02 - T02)
	buffer.writef64(Buf, 24, C03 - T03)
	buffer.writef64(Buf, 32, C04 - T04)
	buffer.writef64(Buf, 40, C05 - T05)
	buffer.writef64(Buf, 48, C06 - T06)
	buffer.writef64(Buf, 56, C07 - T07)
	buffer.writef64(Buf, 64, C08 - T08)
	buffer.writef64(Buf, 72, C09 - T09)
	buffer.writef64(Buf, 80, C10 - T10)
	buffer.writef64(Buf, 88, C11 - T11)

	return Buf
end

function FieldPrime.Square(ElementA: buffer, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local D00 = A00 * 2
	local D01 = A01 * 2
	local D02 = A02 * 2
	local D03 = A03 * 2
	local D04 = A04 * 2
	local D05 = A05 * 2
	local D06 = A06 * 2
	local D07 = A07 * 2
	local D08 = A08 * 2
	local D09 = A09 * 2
	local D10 = A10 * 2

	local ReductionFactor = 19 / 2 ^ 255

	local H00 = A11 * D01 + A10 * D02 + A09 * D03 + A08 * D04 + A07 * D05 + A06 * A06
	local H01 = A11 * D02 + A10 * D03 + A09 * D04 + A08 * D05 + A07 * D06
	local H02 = A11 * D03 + A10 * D04 + A09 * D05 + A08 * D06 + A07 * A07
	local H03 = A11 * D04 + A10 * D05 + A09 * D06 + A08 * D07
	local H04 = A11 * D05 + A10 * D06 + A09 * D07 + A08 * A08
	local H05 = A11 * D06 + A10 * D07 + A09 * D08
	local H06 = A11 * D07 + A10 * D08 + A09 * A09
	local H07 = A11 * D08 + A10 * D09
	local H08 = A11 * D09 + A10 * A10
	local H09 = A11 * D10
	local H10 = A11 * A11

	local L00 = A00 * A00
	local L01 = A01 * D00
	local L02 = A02 * D00 + A01 * A01
	local L03 = A03 * D00 + A02 * D01
	local L04 = A04 * D00 + A03 * D01 + A02 * A02
	local L05 = A05 * D00 + A04 * D01 + A03 * D02
	local L06 = A06 * D00 + A05 * D01 + A04 * D02 + A03 * A03
	local L07 = A07 * D00 + A06 * D01 + A05 * D02 + A04 * D03
	local L08 = A08 * D00 + A07 * D01 + A06 * D02 + A05 * D03 + A04 * A04
	local L09 = A09 * D00 + A08 * D01 + A07 * D02 + A06 * D03 + A05 * D04
	local L10 = A10 * D00 + A09 * D01 + A08 * D02 + A07 * D03 + A06 * D04 + A05 * A05
	local L11 = A11 * D00 + A10 * D01 + A09 * D02 + A08 * D03 + A07 * D04 + A06 * D05

	local Result = Storage or buffer.create(SIZE)
	buffer.writef64(Result, 0, H00 * ReductionFactor + L00)
	buffer.writef64(Result, 8, H01 * ReductionFactor + L01)
	buffer.writef64(Result, 16, H02 * ReductionFactor + L02)
	buffer.writef64(Result, 24, H03 * ReductionFactor + L03)
	buffer.writef64(Result, 32, H04 * ReductionFactor + L04)
	buffer.writef64(Result, 40, H05 * ReductionFactor + L05)
	buffer.writef64(Result, 48, H06 * ReductionFactor + L06)
	buffer.writef64(Result, 56, H07 * ReductionFactor + L07)
	buffer.writef64(Result, 64, H08 * ReductionFactor + L08)
	buffer.writef64(Result, 72, H09 * ReductionFactor + L09)
	buffer.writef64(Result, 80, H10 * ReductionFactor + L10)
	buffer.writef64(Result, 88, L11)

	return FieldPrime.Carry(Result, Result)
end

function FieldPrime.KMul(ElementA: buffer, SmallK: number, Storage: buffer?): buffer
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11

	A00 *= SmallK
	A01 *= SmallK
	A02 *= SmallK
	A03 *= SmallK
	A04 *= SmallK
	A05 *= SmallK
	A06 *= SmallK
	A07 *= SmallK
	A08 *= SmallK
	A09 *= SmallK
	A10 *= SmallK
	A11 *= SmallK

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306
	A00 += 19 / 2 ^ 255 * C11

	C00 = A00 + 3 * 2 ^ 73 - 3 * 2 ^ 73
	A01 += C00
	C01 = A01 + 3 * 2 ^ 94 - 3 * 2 ^ 94
	A02 += C01
	C02 = A02 + 3 * 2 ^ 115 - 3 * 2 ^ 115
	A03 += C02
	C03 = A03 + 3 * 2 ^ 136 - 3 * 2 ^ 136
	A04 += C03
	C04 = A04 + 3 * 2 ^ 158 - 3 * 2 ^ 158
	A05 += C04
	C05 = A05 + 3 * 2 ^ 179 - 3 * 2 ^ 179
	A06 += C05
	C06 = A06 + 3 * 2 ^ 200 - 3 * 2 ^ 200
	A07 += C06
	C07 = A07 + 3 * 2 ^ 221 - 3 * 2 ^ 221
	A08 += C07
	C08 = A08 + 3 * 2 ^ 243 - 3 * 2 ^ 243
	A09 += C08
	C09 = A09 + 3 * 2 ^ 264 - 3 * 2 ^ 264
	A10 += C09
	C10 = A10 + 3 * 2 ^ 285 - 3 * 2 ^ 285
	A11 = A11 - C11 + C10

	C11 = A11 + 3 * 2 ^ 306 - 3 * 2 ^ 306

	local Buf = Storage or buffer.create(SIZE)

	buffer.writef64(Buf, 0, A00 - C00 + 19 / 2 ^ 255 * C11)
	buffer.writef64(Buf, 8, A01 - C01)
	buffer.writef64(Buf, 16, A02 - C02)
	buffer.writef64(Buf, 24, A03 - C03)
	buffer.writef64(Buf, 32, A04 - C04)
	buffer.writef64(Buf, 40, A05 - C05)
	buffer.writef64(Buf, 48, A06 - C06)
	buffer.writef64(Buf, 56, A07 - C07)
	buffer.writef64(Buf, 64, A08 - C08)
	buffer.writef64(Buf, 72, A09 - C09)
	buffer.writef64(Buf, 80, A10 - C10)
	buffer.writef64(Buf, 88, A11 - C11)

	return Buf
end

function FieldPrime.NSquare(ElementA: buffer, SquareCount: number, StoreInBuffer: boolean?): buffer
	local Square = FieldPrime.Square
	if StoreInBuffer then
		for _ = 1, SquareCount do
			Square(ElementA, ElementA)
		end

		return ElementA
	else
		for _ = 1, SquareCount do
			ElementA = Square(ElementA)
		end

		return ElementA
	end
end

function FieldPrime.Invert(ElementA: buffer, Storage: buffer?): buffer
	local Mul = FieldPrime.Mul

	local A2 = FieldPrime.Square(ElementA)
	local A9 = Mul(ElementA, FieldPrime.NSquare(A2, 2))
	local A11 = Mul(A9, A2)

	local X5 = Mul(FieldPrime.Square(A11), A9)
	local X10 = Mul(FieldPrime.NSquare(X5, 5), X5)
	local X20 = Mul(FieldPrime.NSquare(X10, 10), X10)
	local X40 = Mul(FieldPrime.NSquare(X20, 20), X20)
	local X50 = Mul(FieldPrime.NSquare(X40, 10), X10)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)

	return Mul(FieldPrime.NSquare(X250, 5), A11, Storage)
end

function FieldPrime.SqrtDiv(ElementU: buffer, ElementV: buffer): buffer?
	local Mul = FieldPrime.Mul
	local Square = FieldPrime.Square
	local Carry = FieldPrime.Carry

	Carry(ElementU, ElementU)

	local V2 = Square(ElementV)
	local V3 = Mul(ElementV, V2)
	local UV3 = Mul(ElementU, V3)
	local V4 = Square(V2)
	local UV7 = Mul(UV3, V4)

	local X2 = Mul(Square(UV7), UV7)
	local X4 = Mul(FieldPrime.NSquare(X2, 2), X2)
	local X8 = Mul(FieldPrime.NSquare(X4, 4), X4)
	local X16 = Mul(FieldPrime.NSquare(X8, 8), X8)
	local X18 = Mul(FieldPrime.NSquare(X16, 2), X2)
	local X32 = Mul(FieldPrime.NSquare(X16, 16), X16)
	local X50 = Mul(FieldPrime.NSquare(X32, 18), X18)
	local X100 = Mul(FieldPrime.NSquare(X50, 50), X50)
	local X200 = Mul(FieldPrime.NSquare(X100, 100), X100)
	local X250 = Mul(FieldPrime.NSquare(X200, 50), X50)
	local PowerResult = Mul(FieldPrime.NSquare(X250, 2), UV7)

	local CandidateB = Mul(UV3, PowerResult)
	local B2 = Square(CandidateB)
	local VB2 = Mul(ElementV, B2)

	if not FieldPrime.Eq(VB2, ElementU) then
		CandidateB = Mul(CandidateB, SQUARES)
		B2 = Square(CandidateB)
		VB2 = Mul(ElementV, B2)
	end

	if FieldPrime.Eq(VB2, ElementU) then
		return CandidateB
	else
		return nil
	end
end

function FieldPrime.Encode(ElementA: buffer): buffer
	ElementA = FieldPrime.Canonicalize(ElementA)
	local A00, A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, A11 =
		buffer.readf64(ElementA, 0), buffer.readf64(ElementA, 8),
		buffer.readf64(ElementA, 16), buffer.readf64(ElementA, 24),
		buffer.readf64(ElementA, 32), buffer.readf64(ElementA, 40),
		buffer.readf64(ElementA, 48), buffer.readf64(ElementA, 56),
		buffer.readf64(ElementA, 64), buffer.readf64(ElementA, 72),
		buffer.readf64(ElementA, 80), buffer.readf64(ElementA, 88)

	local Buf = buffer.create(32)
	local ByteIndex = 0
	local Accumulator = A00

	local Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	local Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A01 / 2 ^ 16

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	local Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A02 / 2 ^ 40

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A03 / 2 ^ 64

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A04 / 2 ^ 80

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A05 / 2 ^ 104

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A06 / 2 ^ 128

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A07 / 2 ^ 144

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A08 / 2 ^ 168

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A09 / 2 ^ 192

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Accumulator += A10 / 2 ^ 208

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)
	Accumulator = (Accumulator - Byte2) / 256
	ByteIndex += 1

	Accumulator += A11 / 2 ^ 232

	Byte0 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte0)
	Accumulator = (Accumulator - Byte0) / 256
	ByteIndex += 1

	Byte1 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte1)
	Accumulator = (Accumulator - Byte1) / 256
	ByteIndex += 1

	Byte2 = Accumulator % 256
	buffer.writeu8(Buf, ByteIndex, Byte2)

	return Buf
end

function FieldPrime.Decode(EncodedBytes: buffer): buffer
	local B0, B1, B2 = buffer.readu8(EncodedBytes, 0), buffer.readu8(EncodedBytes, 1), buffer.readu8(EncodedBytes, 2)
	local W00 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 3), buffer.readu8(EncodedBytes, 4), buffer.readu8(EncodedBytes, 5)
	local W01 = B0 + B1 * 256 + B2 * 65536

	local W02 = buffer.readu16(EncodedBytes, 6)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 8), buffer.readu8(EncodedBytes, 9), buffer.readu8(EncodedBytes, 10)
	local W03 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 11), buffer.readu8(EncodedBytes, 12), buffer.readu8(EncodedBytes, 13)
	local W04 = B0 + B1 * 256 + B2 * 65536

	local W05 = buffer.readu16(EncodedBytes, 14)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 16), buffer.readu8(EncodedBytes, 17), buffer.readu8(EncodedBytes, 18)
	local W06 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 19), buffer.readu8(EncodedBytes, 20), buffer.readu8(EncodedBytes, 21)
	local W07 = B0 + B1 * 256 + B2 * 65536

	local W08 = buffer.readu16(EncodedBytes, 22)

	B0, B1, B2 = buffer.readu8(EncodedBytes, 24), buffer.readu8(EncodedBytes, 25), buffer.readu8(EncodedBytes, 26)
	local W09 = B0 + B1 * 256 + B2 * 65536

	B0, B1, B2 = buffer.readu8(EncodedBytes, 27), buffer.readu8(EncodedBytes, 28), buffer.readu8(EncodedBytes, 29)
	local W10 = B0 + B1 * 256 + B2 * 65536

	local W11 = buffer.readu16(EncodedBytes, 30) % 32768

	local Buf = buffer.create(SIZE)

	buffer.writef64(Buf, 0, W00)
	buffer.writef64(Buf, 8, W01 * 2 ^ 24)
	buffer.writef64(Buf, 16, W02 * 2 ^ 48)
	buffer.writef64(Buf, 24, W03 * 2 ^ 64)
	buffer.writef64(Buf, 32, W04 * 2 ^ 88)
	buffer.writef64(Buf, 40, W05 * 2 ^ 112)
	buffer.writef64(Buf, 48, W06 * 2 ^ 128)
	buffer.writef64(Buf, 56, W07 * 2 ^ 152)
	buffer.writef64(Buf, 64, W08 * 2 ^ 176)
	buffer.writef64(Buf, 72, W09 * 2 ^ 192)
	buffer.writef64(Buf, 80, W10 * 2 ^ 216)
	buffer.writef64(Buf, 88, W11 * 2 ^ 240)

	return FieldPrime.Carry(Buf, Buf)
end

function FieldPrime.Eqz(ElementA: buffer): boolean
	local Canonical = FieldPrime.Canonicalize(ElementA)
	local C00, C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11 =
		buffer.readf64(Canonical, 0), buffer.readf64(Canonical, 8),
		buffer.readf64(Canonical, 16), buffer.readf64(Canonical, 24),
		buffer.readf64(Canonical, 32), buffer.readf64(Canonical, 40),
		buffer.readf64(Canonical, 48), buffer.readf64(Canonical, 56),
		buffer.readf64(Canonical, 64), buffer.readf64(Canonical, 72),
		buffer.readf64(Canonical, 80), buffer.readf64(Canonical, 88)

	return C00 + C01 + C02 + C03 + C04 + C05 + C06 + C07 + C08 + C09 + C10 + C11 == 0
end

return FieldPrime
end)()

local __RLS_Edwards25519 = (function()
--[=[
	Cryptography library: Edwards25519

	Return type: varies by function
	Example usage:
		local Edwards = require("Edwards25519")
		local FieldQuadratic = require("FieldQuadratic")

		--------Usage Case 1: Point addition--------
		local Point1 = Edwards.Decode(SomeEncodedBuffer)
		local Point2 = Edwards.Decode(AnotherEncodedBuffer)
		local NielsPoint2 = Edwards.Niels(Point2)
		local Sum = Edwards.Add(Point1, NielsPoint2)

		--------Usage Case 2: Scalar multiplication with buffer-based bits--------
		local SomeScalar = FieldQuadratic.Decode(ScalarBytes)
		local ScalarBits, BitCount = FieldQuadratic.Bits(SomeScalar)
		local Result = Edwards.MulG(ScalarBits, BitCount)
		local EncodedResult = Edwards.Encode(Result)
--]=]

--!strict
--!optimize 2
--!native

local FieldPrime = __RLS_FieldPrime
local POINT_SIZE = 416
local COORD_SIZE = 104
local AFFINE_NIELS_SIZE = 312
local BASE_RADIX_WIDTH = 6
local BASE_POINT_ROW = 2 ^ BASE_RADIX_WIDTH / 2

local CURVE_D = FieldPrime.Mul(FieldPrime.Num(-121665), FieldPrime.Invert(FieldPrime.Num(121666)))
local CURVE_K = FieldPrime.KMul(CURVE_D, 2)

local IDENTITY_O = buffer.create(POINT_SIZE) do
	buffer.copy(IDENTITY_O, 0, FieldPrime.Num(0), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 2 * COORD_SIZE, FieldPrime.Num(1), 0, COORD_SIZE)
	buffer.copy(IDENTITY_O, 3 * COORD_SIZE, FieldPrime.Num(0), 0, COORD_SIZE)
end

local COORD_BUFFER_0 = buffer.create(COORD_SIZE)
local COORD_BUFFER_1 = buffer.create(COORD_SIZE)
local COORD_BUFFER_2 = buffer.create(COORD_SIZE)
local COORD_BUFFER_3 = buffer.create(COORD_SIZE)
local COORD_BUFFER_4 = buffer.create(COORD_SIZE)
local COORD_BUFFER_5 = buffer.create(COORD_SIZE)
local COORD_BUFFER_6 = buffer.create(COORD_SIZE)
local COORD_BUFFER_7 = buffer.create(COORD_SIZE)

local MUL_RESULT_POINT = buffer.create(POINT_SIZE)
local MUL_NIELS_POINT = buffer.create(POINT_SIZE)
local MUL_DOUBLE_X = buffer.create(COORD_SIZE)
local MUL_DOUBLE_Y = buffer.create(COORD_SIZE)
local MUL_DOUBLE_Z = buffer.create(COORD_SIZE)
local MUL_DOUBLE_A = buffer.create(COORD_SIZE)
local MUL_DOUBLE_B = buffer.create(COORD_SIZE)
local MUL_DOUBLE_E = buffer.create(COORD_SIZE)
local MUL_DOUBLE_G = buffer.create(COORD_SIZE)
local MUL_P1X = buffer.create(COORD_SIZE)
local MUL_P1Y = buffer.create(COORD_SIZE)
local MUL_P1Z = buffer.create(COORD_SIZE)
local MUL_P1T = buffer.create(COORD_SIZE)
local MUL_N2P = buffer.create(COORD_SIZE)
local MUL_N2M = buffer.create(COORD_SIZE)
local MUL_N2Z = buffer.create(COORD_SIZE)
local MUL_N2T = buffer.create(COORD_SIZE)
local MUL_TMP = buffer.create(COORD_SIZE)

local MULG_RESULT_POINT = buffer.create(POINT_SIZE)
local MULG_AFFINE_NIELS = buffer.create(AFFINE_NIELS_SIZE)
local MULG_DUMMY_POINT = buffer.create(POINT_SIZE)
local MULG_P1X = buffer.create(COORD_SIZE)
local MULG_P1Y = buffer.create(COORD_SIZE)
local MULG_P1Z = buffer.create(COORD_SIZE)
local MULG_P1T = buffer.create(COORD_SIZE)
local MULG_N2P = buffer.create(COORD_SIZE)
local MULG_N2M = buffer.create(COORD_SIZE)
local MULG_N2T = buffer.create(COORD_SIZE)
local MULG_TMP = buffer.create(COORD_SIZE)

local NAF_TABLE_DOUBLED = buffer.create(POINT_SIZE)
local NAF_TABLE_P1X = buffer.create(COORD_SIZE)
local NAF_TABLE_P1Y = buffer.create(COORD_SIZE)
local NAF_TABLE_P1Z = buffer.create(COORD_SIZE)
local NAF_TABLE_P1T = buffer.create(COORD_SIZE)
local NAF_TABLE_N2P = buffer.create(COORD_SIZE)
local NAF_TABLE_N2M = buffer.create(COORD_SIZE)
local NAF_TABLE_N2Z = buffer.create(COORD_SIZE)
local NAF_TABLE_N2T = buffer.create(COORD_SIZE)
local NAF_TABLE_TMP = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_P = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_M = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_Z = buffer.create(COORD_SIZE)
local NAF_TABLE_DBL_T = buffer.create(COORD_SIZE)

local NAF_OUTPUT = buffer.create(512 * 8)
local RADIX_OUTPUT = buffer.create(272 * 8)

local BASEPONT_G: buffer? = nil
local AFFINE_BASEPOINT_TABLE: buffer? = nil

local function GetCoord(Point: buffer, Index: number, Storage: buffer?): buffer
	local Coord = Storage or buffer.create(COORD_SIZE)
	buffer.copy(Coord, 0, Point, Index * COORD_SIZE, COORD_SIZE)
	return Coord
end

local Edwards25519 = {}

function Edwards25519.Double(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)

	local SquaredA = FieldPrime.Square(Point1X)
	local SquaredB = FieldPrime.Square(Point1Y)
	FieldPrime.Square(Point1Z, Point1Z)
	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local DoubledD = Point1Z
	local SumE = FieldPrime.Add(SquaredA, SquaredB)
	FieldPrime.Add(Point1X, Point1Y, Point1X)
	local SumF = Point1X
	local SquaredG = FieldPrime.Square(SumF)
	FieldPrime.Sub(SquaredG, SumE, SquaredG)
	FieldPrime.Carry(SquaredG, SquaredG)
	local DiffH = SquaredG
	FieldPrime.Sub(SquaredB, SquaredA, SquaredB)
	local DiffI = SquaredB
	FieldPrime.Sub(DoubledD, DiffI, DoubledD)
	FieldPrime.Carry(DoubledD, DoubledD)
	local DiffJ = DoubledD

	local NewX = FieldPrime.Mul(DiffH, DiffJ)
	local NewY = FieldPrime.Mul(DiffI, SumE)
	FieldPrime.Mul(DiffJ, DiffI, DiffJ)
	local NewZ = DiffJ
	FieldPrime.Mul(DiffH, SumE, DiffH)
	local NewT = DiffH

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Add(Point1: buffer, NielsPoint2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels1Plus = GetCoord(NielsPoint2, 0, COORD_BUFFER_4)
	local Niels1Minus = GetCoord(NielsPoint2, 1, COORD_BUFFER_5)
	local Niels1Z = GetCoord(NielsPoint2, 2, COORD_BUFFER_6)
	local Niels1T = GetCoord(NielsPoint2, 3, COORD_BUFFER_7)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels1Minus, DiffA)
	local ProductB = DiffA

	local SumC = FieldPrime.Add(Point1Y, Point1X)
	FieldPrime.Mul(SumC, Niels1Plus, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels1T, Point1T)
	local ProductE = Point1T

	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)

	FieldPrime.Add(ProductF, ProductE, ProductF)
	local SumI = ProductF

	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	FieldPrime.Mul(DiffH, SumI, DiffH)
	local NewZ = DiffH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Sub(Point1: buffer, NielsPoint2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels1Plus = GetCoord(NielsPoint2, 0, COORD_BUFFER_4)
	local Niels1Minus = GetCoord(NielsPoint2, 1, COORD_BUFFER_5)
	local Niels1Z = GetCoord(NielsPoint2, 2, COORD_BUFFER_6)
	local Niels1T = GetCoord(NielsPoint2, 3, COORD_BUFFER_7)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels1Plus, DiffA)
	local ProductB = DiffA
	FieldPrime.Add(Point1Y, Point1X, Point1Y)
	local SumC = Point1Y
	FieldPrime.Mul(SumC, Niels1Minus, SumC)
	local ProductD = SumC
	FieldPrime.Mul(Point1T, Niels1T, Point1T)
	local ProductE = Point1T
	FieldPrime.Mul(Point1Z, Niels1Z, Point1Z)
	local ProductF = Point1Z
	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	FieldPrime.Mul(SumH, DiffI, SumH)
	local NewZ = SumH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Niels(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local PlusN3 = FieldPrime.Add(Point1Y, Point1X)
	local MinusN3 = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local DoubledN3Z = Point1Z
	FieldPrime.Mul(Point1T, CURVE_K, Point1T)
	local ScaledN3T = Point1T

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, PlusN3, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, MinusN3, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, DoubledN3Z, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, ScaledN3T, 0, COORD_SIZE)

	return Result
end

function Edwards25519.AffineNiels(Point1: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local YPlusX = FieldPrime.Add(Point1Y, Point1X)
	local YMinusX = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(Point1T, CURVE_K, Point1T)
	local T2d = Point1T

	local Result = Storage or buffer.create(AFFINE_NIELS_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, YPlusX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, YMinusX, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, T2d, 0, COORD_SIZE)

	return Result
end

function Edwards25519.AddAffine(Point1: buffer, AffineNiels2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels2YPlusX = GetCoord(AffineNiels2, 0, COORD_BUFFER_4)
	local Niels2YMinusX = GetCoord(AffineNiels2, 1, COORD_BUFFER_5)
	local Niels2T2d = GetCoord(AffineNiels2, 2, COORD_BUFFER_6)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels2YMinusX, DiffA)
	local ProductB = DiffA

	local SumC = FieldPrime.Add(Point1Y, Point1X)
	FieldPrime.Mul(SumC, Niels2YPlusX, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels2T2d, Point1T)
	local ProductE = Point1T

	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local DiffH = FieldPrime.Sub(ProductF, ProductE)

	FieldPrime.Add(ProductF, ProductE, ProductF)
	local SumI = ProductF

	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, DiffH)
	local NewY = FieldPrime.Mul(SumI, SumJ)
	FieldPrime.Mul(DiffH, SumI, DiffH)
	local NewZ = DiffH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.SubAffine(Point1: buffer, AffineNiels2: buffer, Storage: buffer?): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)
	local Point1T = GetCoord(Point1, 3, COORD_BUFFER_3)

	local Niels2YPlusX = GetCoord(AffineNiels2, 0, COORD_BUFFER_4)
	local Niels2YMinusX = GetCoord(AffineNiels2, 1, COORD_BUFFER_5)
	local Niels2T2d = GetCoord(AffineNiels2, 2, COORD_BUFFER_6)

	local DiffA = FieldPrime.Sub(Point1Y, Point1X)
	FieldPrime.Mul(DiffA, Niels2YPlusX, DiffA)
	local ProductB = DiffA

	FieldPrime.Add(Point1Y, Point1X, Point1Y)
	local SumC = Point1Y
	FieldPrime.Mul(SumC, Niels2YMinusX, SumC)
	local ProductD = SumC

	FieldPrime.Mul(Point1T, Niels2T2d, Point1T)
	local ProductE = Point1T

	FieldPrime.Add(Point1Z, Point1Z, Point1Z)
	local ProductF = Point1Z

	local DiffG = FieldPrime.Sub(ProductD, ProductB)
	local SumH = FieldPrime.Add(ProductF, ProductE)
	local DiffI = FieldPrime.Sub(ProductF, ProductE)
	FieldPrime.Add(ProductD, ProductB, ProductD)
	local SumJ = ProductD

	local NewX = FieldPrime.Mul(DiffG, SumH)
	local NewY = FieldPrime.Mul(DiffI, SumJ)
	FieldPrime.Mul(SumH, DiffI, SumH)
	local NewZ = SumH
	FieldPrime.Mul(DiffG, SumJ, DiffG)
	local NewT = DiffG

	local Result = Storage or buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Scale(Point1: buffer): buffer
	local Point1X = GetCoord(Point1, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(Point1, 1, COORD_BUFFER_1)
	local Point1Z = GetCoord(Point1, 2, COORD_BUFFER_2)

	FieldPrime.Invert(Point1Z, Point1Z)
	local ZInverse = Point1Z
	FieldPrime.Mul(Point1X, ZInverse, Point1X)
	local NewX = Point1X
	FieldPrime.Mul(Point1Y, ZInverse, Point1Y)
	local NewY = Point1Y
	local NewZ = FieldPrime.Num(1)
	local NewT = FieldPrime.Mul(NewX, NewY)

	local Result = buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, NewX, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, NewY, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, NewZ, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, NewT, 0, COORD_SIZE)

	return Result
end

function Edwards25519.Encode(Point1: buffer): buffer
	local ScaledPoint = Edwards25519.Scale(Point1)
	local Point1X = GetCoord(ScaledPoint, 0, COORD_BUFFER_0)
	local Point1Y = GetCoord(ScaledPoint, 1, COORD_BUFFER_1)

	local EncodedY = FieldPrime.Encode(Point1Y)
	local CanonicalX = FieldPrime.Canonicalize(Point1X)
	local XSignBit = buffer.readf64(CanonicalX, 0) % 2

	local ResultBuffer = buffer.create(32)
	buffer.copy(ResultBuffer, 0, EncodedY, 0, 32)

	local LastByte = buffer.readu8(ResultBuffer, 31)
	buffer.writeu8(ResultBuffer, 31, LastByte + XSignBit * 128)

	return ResultBuffer
end

function Edwards25519.Decode(EncodedBuffer: buffer): buffer?
	local WorkingBuffer = buffer.create(32)
	buffer.copy(WorkingBuffer, 0, EncodedBuffer, 0, 32)

	local LastByte = buffer.readu8(WorkingBuffer, 31)
	local SignBit = bit32.extract(LastByte, 7)
	buffer.writeu8(WorkingBuffer, 31, bit32.band(LastByte, 0x7F))

	local YCoord = FieldPrime.Decode(WorkingBuffer)
	local YSquared = FieldPrime.Square(YCoord)
	local Numerator = FieldPrime.Sub(YSquared, FieldPrime.Num(1))
	local Denominator = FieldPrime.Mul(YSquared, CURVE_D)
	local DenomPlusOne = FieldPrime.Add(Denominator, FieldPrime.Num(1))

	local XCoord = FieldPrime.SqrtDiv(Numerator, DenomPlusOne)
	if not XCoord then
		return nil
	end

	local CanonicalX = FieldPrime.Canonicalize(XCoord)
	local XSignBit = buffer.readf64(CanonicalX, 0) % 2

	if XSignBit ~= SignBit then
		XCoord = FieldPrime.Carry(FieldPrime.Neg(XCoord))
	end

	local ZCoord = FieldPrime.Num(1)
	local TCoord = FieldPrime.Mul(XCoord, YCoord)

	local Result = buffer.create(POINT_SIZE)
	buffer.copy(Result, 0 * COORD_SIZE, XCoord, 0, COORD_SIZE)
	buffer.copy(Result, 1 * COORD_SIZE, YCoord, 0, COORD_SIZE)
	buffer.copy(Result, 2 * COORD_SIZE, ZCoord, 0, COORD_SIZE)
	buffer.copy(Result, 3 * COORD_SIZE, TCoord, 0, COORD_SIZE)

	return Result
end

local BASEPOINT_BYTES = buffer.create(32) do
	local BasePointHex = {
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66
	}

	for Index = 1, 32 do
		buffer.writeu8(BASEPOINT_BYTES, Index - 1, BasePointHex[Index])
	end

	BASEPONT_G = Edwards25519.Decode(BASEPOINT_BYTES)
end

function Edwards25519.AffineRadixWTable(BasePoint: buffer, RadixWidth: number): buffer
	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	if buffer.len(BasePoint) ~= POINT_SIZE then
		error("Invalid Basepoint", 2)
	end

	local MaxWindows = math.ceil(256 / RadixWidth)
	local MaxRowSize = 2 ^ RadixWidth / 2

	local TableData = buffer.create(MaxWindows * MaxRowSize * AFFINE_NIELS_SIZE)

	local CurrentBasePoint = buffer.create(POINT_SIZE)
	buffer.copy(CurrentBasePoint, 0, BasePoint, 0, POINT_SIZE)

	local AffineNiels = Edwards25519.AffineNiels
	local Add = Edwards25519.Add
	local Double = Edwards25519.Double
	local Scale = Edwards25519.Scale
	local Niels = Edwards25519.Niels
	local NielsSize = AFFINE_NIELS_SIZE

	for WindowIndex = 1, MaxWindows do
		local BaseOffset = ((WindowIndex - 1) * MaxRowSize * NielsSize)
		local WorkingPoint = buffer.create(POINT_SIZE)
		buffer.copy(WorkingPoint, 0, CurrentBasePoint, 0, POINT_SIZE)

		local ScaledPoint = Scale(WorkingPoint)
		local FirstAffineNiels = AffineNiels(ScaledPoint)
		buffer.copy(TableData, BaseOffset, FirstAffineNiels, 0, NielsSize)

		local FirstNiels = Niels(ScaledPoint)

		for Multiple = 2, MaxRowSize do
			Add(WorkingPoint, FirstNiels, WorkingPoint)
			local Scaled = Scale(WorkingPoint)
			local AffineNielsBuffer = AffineNiels(Scaled)

			local Offset = BaseOffset + ((Multiple - 1) * NielsSize)
			buffer.copy(TableData, Offset, AffineNielsBuffer, 0, NielsSize)
		end

		for _ = 1, RadixWidth do
			CurrentBasePoint = Double(CurrentBasePoint)
		end
	end

	return TableData
end

do
	if BASEPONT_G then
		AFFINE_BASEPOINT_TABLE = Edwards25519.AffineRadixWTable(BASEPONT_G, BASE_RADIX_WIDTH)
	end
end

function Edwards25519.GetAffineBasePointTableEntry(WindowIndex: number, Multiple: number, Storage: buffer?): buffer
	if not AFFINE_BASEPOINT_TABLE then
		return buffer.create(0)
	end

	local BaseOffset = ((WindowIndex - 1) * BASE_POINT_ROW * AFFINE_NIELS_SIZE)
	local Offset = BaseOffset + ((Multiple - 1) * AFFINE_NIELS_SIZE)

	local AffineNielsPoint = Storage or buffer.create(AFFINE_NIELS_SIZE)
	buffer.copy(AffineNielsPoint, 0, AFFINE_BASEPOINT_TABLE, Offset, AFFINE_NIELS_SIZE)

	return AffineNielsPoint
end

function Edwards25519.SignedRadixW(ScalarBits: buffer, ScalarBitCount: number, RadixWidth: number): (buffer, number)
	if ScalarBitCount <= 0 or ScalarBitCount > 256 then
		error("Invalid scalar bit count", 2)
	end

	if RadixWidth <= 0 or RadixWidth > 8 then
		error("Invalid Radix width", 2)
	end

	local RadixValue = 2 ^ RadixWidth
	local HalfRadix = RadixValue / 2
	local MaxOutputLength = 272
	local OutputDigits = RADIX_OUTPUT
	local OutputLength, Accumulator = 0, 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		if BitIndex > ScalarBitCount then
			break
		end

		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > RadixValue do
			if OutputLength >= MaxOutputLength then
				error("Output overflow in SignedRadixW")
			end

			local Remainder = Accumulator % RadixValue
			if Remainder >= HalfRadix then
				Remainder -= RadixValue
			end
			Accumulator = (Accumulator - Remainder) / RadixValue
			Multiplier /= RadixValue
			buffer.writef64(OutputDigits, OutputLength * 8, Remainder)
			OutputLength += 1
		end
	end

	return OutputDigits, OutputLength
end

function Edwards25519.WindowedNAF(ScalarBits: buffer, ScalarBitCount: number, WindowWidth: number): (buffer, number)
	local WindowValue = 2 ^ WindowWidth
	local HalfWindow = WindowValue / 2
	local OutputNAF = NAF_OUTPUT
	local OutputLength = 0
	local Accumulator = 0
	local Multiplier = 1

	for BitIndex = 1, ScalarBitCount do
		local BitValue = buffer.readf64(ScalarBits, (BitIndex - 1) * 8)
		Accumulator += BitValue * Multiplier
		Multiplier *= 2

		while BitIndex == ScalarBitCount and Accumulator > 0 or Multiplier > WindowValue do
			if Accumulator % 2 == 0 then
				Accumulator /= 2
				Multiplier /= 2
				buffer.writef64(OutputNAF, OutputLength * 8, 0)
				OutputLength += 1
			else
				local Remainder = Accumulator % WindowValue
				if Remainder >= HalfWindow then
					Remainder -= WindowValue
				end
				Accumulator -= Remainder
				buffer.writef64(OutputNAF, OutputLength * 8, Remainder)
				OutputLength += 1
			end
		end
	end

	while OutputLength > 0 and buffer.readf64(OutputNAF, (OutputLength - 1) * 8) == 0 do
		OutputLength -= 1
	end

	return OutputNAF, OutputLength
end

function Edwards25519.WindowedNAFTable(BasePoint: buffer, WindowWidth: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local CurveK = CURVE_K
	local MaxOddMultiples = 2 ^ WindowWidth

	Edwards25519.Double(BasePoint, NAF_TABLE_DOUBLED)

	local TableData = buffer.create(MaxOddMultiples * PointSize)

	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul

	local P1X = NAF_TABLE_P1X
	local P1Y = NAF_TABLE_P1Y
	local P1Z = NAF_TABLE_P1Z
	local P1T = NAF_TABLE_P1T
	local N2P = NAF_TABLE_N2P
	local N2M = NAF_TABLE_N2M
	local N2Z = NAF_TABLE_N2Z
	local N2T = NAF_TABLE_N2T
	local TMP = NAF_TABLE_TMP
	local DBLP = NAF_TABLE_DBL_P
	local DBLM = NAF_TABLE_DBL_M
	local DBLZ = NAF_TABLE_DBL_Z
	local DBLT = NAF_TABLE_DBL_T
	local Doubled = NAF_TABLE_DOUBLED

	buffer.copy(P1X, 0, Doubled, 0, CoordSize)
	buffer.copy(P1Y, 0, Doubled, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, Doubled, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, Doubled, 3 * CoordSize, CoordSize)

	FAdd(P1Y, P1X, DBLP)
	FSub(P1Y, P1X, DBLM)
	FAdd(P1Z, P1Z, DBLZ)
	FMul(P1T, CurveK, DBLT)

	buffer.copy(P1X, 0, BasePoint, 0, CoordSize)
	buffer.copy(P1Y, 0, BasePoint, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, BasePoint, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, BasePoint, 3 * CoordSize, CoordSize)

	FAdd(P1Y, P1X, N2P)
	FSub(P1Y, P1X, N2M)
	FAdd(P1Z, P1Z, N2Z)
	FMul(P1T, CurveK, N2T)

	buffer.copy(TableData, 0, N2P, 0, CoordSize)
	buffer.copy(TableData, CoordSize, N2M, 0, CoordSize)
	buffer.copy(TableData, 2 * CoordSize, N2Z, 0, CoordSize)
	buffer.copy(TableData, 3 * CoordSize, N2T, 0, CoordSize)

	buffer.copy(P1X, 0, BasePoint, 0, CoordSize)
	buffer.copy(P1Y, 0, BasePoint, CoordSize, CoordSize)
	buffer.copy(P1Z, 0, BasePoint, 2 * CoordSize, CoordSize)
	buffer.copy(P1T, 0, BasePoint, 3 * CoordSize, CoordSize)

	for OddMultiple = 3, MaxOddMultiples, 2 do
		local CurrentOffset = ((OddMultiple - 1) * PointSize)

		FSub(P1Y, P1X, TMP)
		FMul(TMP, DBLM, TMP)
		FAdd(P1Y, P1X, N2P)
		FMul(N2P, DBLP, N2P)
		FMul(P1T, DBLT, P1T)
		FMul(P1Z, DBLZ, P1Z)

		FSub(N2P, TMP, N2M)
		FSub(P1Z, P1T, N2Z)
		FAdd(P1Z, P1T, P1Z)
		FAdd(N2P, TMP, N2P)

		FMul(N2M, N2Z, P1X)
		FMul(P1Z, N2P, P1Y)
		FMul(N2Z, P1Z, P1Z)
		FMul(N2M, N2P, P1T)

		FAdd(P1Y, P1X, N2P)
		FSub(P1Y, P1X, N2M)
		FAdd(P1Z, P1Z, N2Z)
		FMul(P1T, CurveK, N2T)

		buffer.copy(TableData, CurrentOffset, N2P, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + CoordSize, N2M, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + 2 * CoordSize, N2Z, 0, CoordSize)
		buffer.copy(TableData, CurrentOffset + 3 * CoordSize, N2T, 0, CoordSize)
	end

	return TableData
end

function Edwards25519.MulG(ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local AffineNielsSize = AFFINE_NIELS_SIZE
	local IdentityO = IDENTITY_O
	local BaseRadixWidth = BASE_RADIX_WIDTH
	local BasePointRow = BASE_POINT_ROW
	local AffineTable = AFFINE_BASEPOINT_TABLE :: buffer

	local SignedWindows, WindowCount = Edwards25519.SignedRadixW(ScalarBits, ScalarBitCount, BaseRadixWidth)

	local ResultPoint = MULG_RESULT_POINT
	buffer.copy(ResultPoint, 0, IdentityO, 0, PointSize)

	local AffineNielsPoint = MULG_AFFINE_NIELS
	local DummyPoint = MULG_DUMMY_POINT
	buffer.copy(DummyPoint, 0, IdentityO, 0, PointSize)

	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul

	local P1X = MULG_P1X
	local P1Y = MULG_P1Y
	local P1Z = MULG_P1Z
	local P1T = MULG_P1T
	local N2P = MULG_N2P
	local N2M = MULG_N2M
	local N2T = MULG_N2T
	local TMP = MULG_TMP

	for WindowIndex = 1, WindowCount do
		local WindowValue = buffer.readf64(SignedWindows, (WindowIndex - 1) * 8)

		if WindowValue > 0 then
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			local Offset = BaseOffset + ((WindowValue - 1) * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, Offset, AffineNielsSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		elseif WindowValue < 0 then
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			local Offset = BaseOffset + (((-WindowValue) - 1) * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, Offset, AffineNielsSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2P, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2M, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FAdd(P1Z, P1T, N2P)
			FSub(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		else
			local BaseOffset = ((WindowIndex - 1) * BasePointRow * AffineNielsSize)
			buffer.copy(AffineNielsPoint, 0, AffineTable, BaseOffset, AffineNielsSize)

			buffer.copy(P1X, 0, DummyPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, DummyPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, DummyPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, DummyPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, AffineNielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, AffineNielsPoint, CoordSize, CoordSize)
			buffer.copy(N2T, 0, AffineNielsPoint, 2 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FAdd(P1Z, P1Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(DummyPoint, 0, TMP, 0, CoordSize)
			buffer.copy(DummyPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(DummyPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(DummyPoint, 3 * CoordSize, P1X, 0, CoordSize)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

function Edwards25519.Mul(BasePoint: buffer, ScalarBits: buffer, ScalarBitCount: number): buffer
	local PointSize = POINT_SIZE
	local CoordSize = COORD_SIZE
	local IdentityO = IDENTITY_O

	local NAFForm, NAFLength = Edwards25519.WindowedNAF(ScalarBits, ScalarBitCount, 5)
	local MultipleTable = Edwards25519.WindowedNAFTable(BasePoint, 5)

	local ResultPoint = MUL_RESULT_POINT
	buffer.copy(ResultPoint, 0, IdentityO, 0, PointSize)

	local NielsPoint = MUL_NIELS_POINT

	local Square = FieldPrime.Square
	local FAdd = FieldPrime.Add
	local FSub = FieldPrime.Sub
	local FMul = FieldPrime.Mul
	local Carry = FieldPrime.Carry

	local DoubleX = MUL_DOUBLE_X
	local DoubleY = MUL_DOUBLE_Y
	local DoubleZ = MUL_DOUBLE_Z
	local DoubleA = MUL_DOUBLE_A
	local DoubleB = MUL_DOUBLE_B
	local DoubleE = MUL_DOUBLE_E
	local DoubleG = MUL_DOUBLE_G

	local P1X = MUL_P1X
	local P1Y = MUL_P1Y
	local P1Z = MUL_P1Z
	local P1T = MUL_P1T
	local N2P = MUL_N2P
	local N2M = MUL_N2M
	local N2Z = MUL_N2Z
	local N2T = MUL_N2T
	local TMP = MUL_TMP

	for NAFIndex = NAFLength, 1, -1 do
		local NAFDigit = buffer.readf64(NAFForm, (NAFIndex - 1) * 8)

		if NAFDigit == 0 then
			buffer.copy(DoubleX, 0, ResultPoint, 0, CoordSize)
			buffer.copy(DoubleY, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(DoubleZ, 0, ResultPoint, 2 * CoordSize, CoordSize)

			Square(DoubleX, DoubleA)
			Square(DoubleY, DoubleB)
			Square(DoubleZ, DoubleZ)
			FAdd(DoubleZ, DoubleZ, DoubleZ)
			FAdd(DoubleA, DoubleB, DoubleE)
			FAdd(DoubleX, DoubleY, DoubleX)
			Square(DoubleX, DoubleG)
			FSub(DoubleG, DoubleE, DoubleG)
			Carry(DoubleG, DoubleG)
			FSub(DoubleB, DoubleA, DoubleB)
			FSub(DoubleZ, DoubleB, DoubleZ)
			Carry(DoubleZ, DoubleZ)

			FMul(DoubleG, DoubleZ, DoubleX)
			FMul(DoubleB, DoubleE, DoubleY)
			FMul(DoubleZ, DoubleB, DoubleZ)
			FMul(DoubleG, DoubleE, DoubleE)

			buffer.copy(ResultPoint, 0, DoubleX, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, DoubleY, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, DoubleZ, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, DoubleE, 0, CoordSize)

		elseif NAFDigit > 0 then
			buffer.copy(NielsPoint, 0, MultipleTable, ((NAFDigit - 1) * PointSize), PointSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, NielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, NielsPoint, CoordSize, CoordSize)
			buffer.copy(N2Z, 0, NielsPoint, 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, NielsPoint, 3 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2M, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2P, P1X)
			FMul(P1T, N2T, P1T)
			FMul(P1Z, N2Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FSub(P1Z, P1T, N2P)
			FAdd(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)

		else
			buffer.copy(NielsPoint, 0, MultipleTable, (((-NAFDigit) - 1) * PointSize), PointSize)

			buffer.copy(P1X, 0, ResultPoint, 0, CoordSize)
			buffer.copy(P1Y, 0, ResultPoint, CoordSize, CoordSize)
			buffer.copy(P1Z, 0, ResultPoint, 2 * CoordSize, CoordSize)
			buffer.copy(P1T, 0, ResultPoint, 3 * CoordSize, CoordSize)
			buffer.copy(N2P, 0, NielsPoint, 0, CoordSize)
			buffer.copy(N2M, 0, NielsPoint, CoordSize, CoordSize)
			buffer.copy(N2Z, 0, NielsPoint, 2 * CoordSize, CoordSize)
			buffer.copy(N2T, 0, NielsPoint, 3 * CoordSize, CoordSize)

			FSub(P1Y, P1X, TMP)
			FMul(TMP, N2P, TMP)
			FAdd(P1Y, P1X, P1X)
			FMul(P1X, N2M, P1X)
			FMul(P1T, N2T, P1T)
			FMul(P1Z, N2Z, P1Z)

			FSub(P1X, TMP, P1Y)
			FAdd(P1Z, P1T, N2P)
			FSub(P1Z, P1T, P1Z)
			FAdd(P1X, TMP, P1X)

			FMul(P1Y, N2P, TMP)
			FMul(P1Z, P1X, P1T)
			FMul(N2P, P1Z, P1Z)
			FMul(P1Y, P1X, P1X)

			buffer.copy(ResultPoint, 0, TMP, 0, CoordSize)
			buffer.copy(ResultPoint, CoordSize, P1T, 0, CoordSize)
			buffer.copy(ResultPoint, 2 * CoordSize, P1Z, 0, CoordSize)
			buffer.copy(ResultPoint, 3 * CoordSize, P1X, 0, CoordSize)
		end
	end

	local Output = buffer.create(PointSize)
	buffer.copy(Output, 0, ResultPoint, 0, PointSize)
	return Output
end

return Edwards25519
end)()

local __RLS_SHA512 = (function()
--!strict
--!optimize 2
--!native

local K_HI = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	0xca273ece, 0xd186b8c7, 0xeada7dd6, 0xf57d4f7f, 0x06f067aa, 0x0a637dc5, 0x113f9804, 0x1b710b35,
	0x28db77f5, 0x32caab7b, 0x3c9ebe0a, 0x431d67c4, 0x4cc5d4be, 0x597f299c, 0x5fcb6fab, 0x6c44198c,
}

local K_LO = {
	0xd728ae22, 0x23ef65cd, 0xec4d3b2f, 0x8189dbbc, 0xf348b538, 0xb605d019, 0xaf194f9b, 0xda6d8118,
	0xa3030242, 0x45706fbe, 0x4ee4b28c, 0xd5ffb4e2, 0xf27b896f, 0x3b1696b1, 0x25c71235, 0xcf692694,
	0x9ef14ad2, 0x384f25e3, 0x8b8cd5b5, 0x77ac9c65, 0x592b0275, 0x6ea6e483, 0xbd41fbd4, 0x831153b5,
	0xee66dfab, 0x2db43210, 0x98fb213f, 0xbeef0ee4, 0x3da88fc2, 0x930aa725, 0xe003826f, 0x0a0e6e70,
	0x46d22ffc, 0x5c26c926, 0x5ac42aed, 0x9d95b3df, 0x8baf63de, 0x3c77b2a8, 0x47edaee6, 0x1482353b,
	0x4cf10364, 0xbc423001, 0xd0f89791, 0x0654be30, 0xd6ef5218, 0x5565a910, 0x5771202a, 0x32bbd1b8,
	0xb8d2d0c8, 0x5141ab53, 0xdf8eeb99, 0xe19b48a8, 0xc5c95a63, 0xe3418acb, 0x7763e373, 0xd6b2b8a3,
	0x5defb2fc, 0x43172f60, 0xa1f0ab72, 0x1a6439ec, 0x23631e28, 0xde82bde9, 0xb2c67915, 0xe372532b,
	0xea26619c, 0x21c0c207, 0xcde0eb1e, 0xee6ed178, 0x72176fba, 0xa2c898a6, 0xbef90dae, 0x131c471b,
	0x23047d84, 0x40c72493, 0x15c9bebc, 0x9c100d4c, 0xcb3e42b6, 0xfc657e2a, 0x3ad6faec, 0x4a475817,
}

local W_HI = table.create(80) :: {number}
local W_LO = table.create(80) :: {number}
local RESULT_BUFFER = buffer.create(64)

local function PreProcess(Contents: buffer): (buffer, number)
	local ContentLength = buffer.len(Contents)
	local Padding = (128 - ((ContentLength + 17) % 128)) % 128
	local NewLength = ContentLength + 1 + Padding + 16

	local Result = buffer.create(NewLength)
	buffer.copy(Result, 0, Contents)
	buffer.writeu8(Result, ContentLength, 0x80)
	buffer.fill(Result, ContentLength + 1, 0, Padding + 8)

	local BitLength = ContentLength * 8
	local LengthOffset = ContentLength + 1 + Padding + 8

	for Index = 7, 0, -1 do
		buffer.writeu8(Result, LengthOffset + Index, BitLength % 256)
		BitLength = BitLength // 256
	end

	return Result, NewLength
end

local function SHA512(Message: buffer): buffer
	local Blocks, Length = PreProcess(Message)

	local Hi, Lo = W_HI, W_LO
	local KHi, KLo = K_HI, K_LO

	local H1Hi, H2Hi, H3Hi, H4Hi = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local H5Hi, H6Hi, H7Hi, H8Hi = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local H1Lo, H2Lo, H3Lo, H4Lo = 0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1
	local H5Lo, H6Lo, H7Lo, H8Lo = 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179

	for Offset = 0, Length - 1, 128 do
		for T = 1, 16 do
			local ByteOffset = Offset + (T - 1) * 8
			Hi[T] = bit32.byteswap(buffer.readu32(Blocks, ByteOffset))
			Lo[T] = bit32.byteswap(buffer.readu32(Blocks, ByteOffset + 4))
		end

		for T = 17, 80 do
			local P15Hi, P15Lo = Hi[T - 15], Lo[T - 15]
			local P2Hi, P2Lo = Hi[T - 2], Lo[T - 2]

			local S0Lo = bit32.bxor(bit32.rshift(P15Lo, 1) + bit32.lshift(P15Hi, 31), bit32.rshift(P15Lo, 8) + bit32.lshift(P15Hi, 24), bit32.rshift(P15Lo, 7) + bit32.lshift(P15Hi, 25))
			local S1Lo = bit32.bxor(bit32.rshift(P2Lo, 19) + bit32.lshift(P2Hi, 13), bit32.lshift(P2Lo, 3) + bit32.rshift(P2Hi, 29), bit32.rshift(P2Lo, 6) + bit32.lshift(P2Hi, 26))

			local TmpLo = Lo[T - 16] + S0Lo + Lo[T - 7] + S1Lo
			Lo[T] = bit32.bor(TmpLo, 0)
			Hi[T] = bit32.bxor(bit32.rshift(P15Hi, 1) + bit32.lshift(P15Lo, 31), bit32.rshift(P15Hi, 8) + bit32.lshift(P15Lo, 24), bit32.rshift(P15Hi, 7)) +
				bit32.bxor(bit32.rshift(P2Hi, 19) + bit32.lshift(P2Lo, 13), bit32.lshift(P2Hi, 3) + bit32.rshift(P2Lo, 29), bit32.rshift(P2Hi, 6)) +
				Hi[T - 16] + Hi[T - 7] + TmpLo // 0x100000000
		end

		local AHi, ALo = H1Hi, H1Lo
		local BHi, BLo = H2Hi, H2Lo
		local CHi, CLo = H3Hi, H3Lo
		local DHi, DLo = H4Hi, H4Lo
		local EHi, ELo = H5Hi, H5Lo
		local FHi, FLo = H6Hi, H6Lo
		local GHi, GLo = H7Hi, H7Lo
		local HHi, HLo = H8Hi, H8Lo

		for T = 1, 79, 2 do
			local Sigma1Lo = bit32.bxor(bit32.rshift(ELo, 14) + bit32.lshift(EHi, 18), bit32.rshift(ELo, 18) + bit32.lshift(EHi, 14), bit32.lshift(ELo, 23) + bit32.rshift(EHi, 9))
			local Sigma1Hi = bit32.bxor(bit32.rshift(EHi, 14) + bit32.lshift(ELo, 18), bit32.rshift(EHi, 18) + bit32.lshift(ELo, 14), bit32.lshift(EHi, 23) + bit32.rshift(ELo, 9))
			local Sigma0Lo = bit32.bxor(bit32.rshift(ALo, 28) + bit32.lshift(AHi, 4), bit32.lshift(ALo, 30) + bit32.rshift(AHi, 2), bit32.lshift(ALo, 25) + bit32.rshift(AHi, 7))
			local Sigma0Hi = bit32.bxor(bit32.rshift(AHi, 28) + bit32.lshift(ALo, 4), bit32.lshift(AHi, 30) + bit32.rshift(ALo, 2), bit32.lshift(AHi, 25) + bit32.rshift(ALo, 7))
			local ChLo = bit32.band(ELo, FLo) + bit32.band(-1 - ELo, GLo)
			local ChHi = bit32.band(EHi, FHi) + bit32.band(-1 - EHi, GHi)
			local MajLo = bit32.band(CLo, BLo) + bit32.band(ALo, bit32.bxor(CLo, BLo))
			local MajHi = bit32.band(CHi, BHi) + bit32.band(AHi, bit32.bxor(CHi, BHi))

			local T1Lo = HLo + Sigma1Lo + ChLo + KLo[T] + Lo[T]
			local T1Hi = HHi + Sigma1Hi + ChHi + KHi[T] + Hi[T] + T1Lo // 0x100000000
			T1Lo = bit32.bor(T1Lo, 0)

			HHi, HLo = GHi, GLo
			GHi, GLo = FHi, FLo
			FHi, FLo = EHi, ELo

			local ELoNew = DLo + T1Lo
			EHi = DHi + T1Hi + ELoNew // 0x100000000
			ELo = bit32.bor(ELoNew, 0)

			DHi, DLo = CHi, CLo
			CHi, CLo = BHi, BLo
			BHi, BLo = AHi, ALo

			local ALoNew = T1Lo + Sigma0Lo + MajLo
			AHi = T1Hi + Sigma0Hi + MajHi + ALoNew // 0x100000000
			ALo = bit32.bor(ALoNew, 0)

			local T2 = T + 1
			Sigma1Lo = bit32.bxor(bit32.rshift(ELo, 14) + bit32.lshift(EHi, 18), bit32.rshift(ELo, 18) + bit32.lshift(EHi, 14), bit32.lshift(ELo, 23) + bit32.rshift(EHi, 9))
			Sigma1Hi = bit32.bxor(bit32.rshift(EHi, 14) + bit32.lshift(ELo, 18), bit32.rshift(EHi, 18) + bit32.lshift(ELo, 14), bit32.lshift(EHi, 23) + bit32.rshift(ELo, 9))
			Sigma0Lo = bit32.bxor(bit32.rshift(ALo, 28) + bit32.lshift(AHi, 4), bit32.lshift(ALo, 30) + bit32.rshift(AHi, 2), bit32.lshift(ALo, 25) + bit32.rshift(AHi, 7))
			Sigma0Hi = bit32.bxor(bit32.rshift(AHi, 28) + bit32.lshift(ALo, 4), bit32.lshift(AHi, 30) + bit32.rshift(ALo, 2), bit32.lshift(AHi, 25) + bit32.rshift(ALo, 7))
			ChLo = bit32.band(ELo, FLo) + bit32.band(-1 - ELo, GLo)
			ChHi = bit32.band(EHi, FHi) + bit32.band(-1 - EHi, GHi)
			MajLo = bit32.band(CLo, BLo) + bit32.band(ALo, bit32.bxor(CLo, BLo))
			MajHi = bit32.band(CHi, BHi) + bit32.band(AHi, bit32.bxor(CHi, BHi))

			T1Lo = HLo + Sigma1Lo + ChLo + KLo[T2] + Lo[T2]
			T1Hi = HHi + Sigma1Hi + ChHi + KHi[T2] + Hi[T2] + T1Lo // 0x100000000
			T1Lo = bit32.bor(T1Lo, 0)

			HHi, HLo = GHi, GLo
			GHi, GLo = FHi, FLo
			FHi, FLo = EHi, ELo

			ELoNew = DLo + T1Lo
			EHi = DHi + T1Hi + ELoNew // 0x100000000
			ELo = bit32.bor(ELoNew, 0)

			DHi, DLo = CHi, CLo
			CHi, CLo = BHi, BLo
			BHi, BLo = AHi, ALo

			ALoNew = T1Lo + Sigma0Lo + MajLo
			AHi = T1Hi + Sigma0Hi + MajHi + ALoNew // 0x100000000
			ALo = bit32.bor(ALoNew, 0)
		end

		H1Lo = H1Lo + ALo
		H1Hi = bit32.bor(H1Hi + AHi + H1Lo // 0x100000000, 0)
		H1Lo = bit32.bor(H1Lo, 0)

		H2Lo = H2Lo + BLo
		H2Hi = bit32.bor(H2Hi + BHi + H2Lo // 0x100000000, 0)
		H2Lo = bit32.bor(H2Lo, 0)

		H3Lo = H3Lo + CLo
		H3Hi = bit32.bor(H3Hi + CHi + H3Lo // 0x100000000, 0)
		H3Lo = bit32.bor(H3Lo, 0)

		H4Lo = H4Lo + DLo
		H4Hi = bit32.bor(H4Hi + DHi + H4Lo // 0x100000000, 0)
		H4Lo = bit32.bor(H4Lo, 0)

		H5Lo = H5Lo + ELo
		H5Hi = bit32.bor(H5Hi + EHi + H5Lo // 0x100000000, 0)
		H5Lo = bit32.bor(H5Lo, 0)

		H6Lo = H6Lo + FLo
		H6Hi = bit32.bor(H6Hi + FHi + H6Lo // 0x100000000, 0)
		H6Lo = bit32.bor(H6Lo, 0)

		H7Lo = H7Lo + GLo
		H7Hi = bit32.bor(H7Hi + GHi + H7Lo // 0x100000000, 0)
		H7Lo = bit32.bor(H7Lo, 0)

		H8Lo = H8Lo + HLo
		H8Hi = bit32.bor(H8Hi + HHi + H8Lo // 0x100000000, 0)
		H8Lo = bit32.bor(H8Lo, 0)
	end

	buffer.writeu32(RESULT_BUFFER, 0, bit32.byteswap(H1Hi))
	buffer.writeu32(RESULT_BUFFER, 4, bit32.byteswap(H1Lo))
	buffer.writeu32(RESULT_BUFFER, 8, bit32.byteswap(H2Hi))
	buffer.writeu32(RESULT_BUFFER, 12, bit32.byteswap(H2Lo))
	buffer.writeu32(RESULT_BUFFER, 16, bit32.byteswap(H3Hi))
	buffer.writeu32(RESULT_BUFFER, 20, bit32.byteswap(H3Lo))
	buffer.writeu32(RESULT_BUFFER, 24, bit32.byteswap(H4Hi))
	buffer.writeu32(RESULT_BUFFER, 28, bit32.byteswap(H4Lo))
	buffer.writeu32(RESULT_BUFFER, 32, bit32.byteswap(H5Hi))
	buffer.writeu32(RESULT_BUFFER, 36, bit32.byteswap(H5Lo))
	buffer.writeu32(RESULT_BUFFER, 40, bit32.byteswap(H6Hi))
	buffer.writeu32(RESULT_BUFFER, 44, bit32.byteswap(H6Lo))
	buffer.writeu32(RESULT_BUFFER, 48, bit32.byteswap(H7Hi))
	buffer.writeu32(RESULT_BUFFER, 52, bit32.byteswap(H7Lo))
	buffer.writeu32(RESULT_BUFFER, 56, bit32.byteswap(H8Hi))
	buffer.writeu32(RESULT_BUFFER, 60, bit32.byteswap(H8Lo))

	return RESULT_BUFFER
end

return SHA512
end)()

local __RLS_PublicKeyBase64Url = "d_3gZiZBIfl8DkJ-oYc_Nk0vKgax2W7PUeXBzU9wxnE"

local function __RLS_DecodeBase64Url(value)
	if type(value) ~= "string" or #value == 0 or #value % 4 == 1 or value:match("^[%w_-]+$") == nil then
		return nil
	end
	local alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	local lookup = {}
	for index = 1, #alphabet do
		lookup[alphabet:sub(index, index)] = index - 1
	end
	local bytes = {}
	local accumulator = 0
	local bitCount = 0
	for index = 1, #value do
		local mapped = lookup[value:sub(index, index)]
		if mapped == nil then return nil end
		accumulator = accumulator * 64 + mapped
		bitCount += 6
		while bitCount >= 8 do
			bitCount -= 8
			local divisor = 2 ^ bitCount
			bytes[#bytes + 1] = string.char(math.floor(accumulator / divisor) % 256)
			accumulator %= divisor
		end
	end
	if bitCount > 0 and accumulator ~= 0 then return nil end
	return table.concat(bytes)
end

local function __RLS_ConcatBuffers(...)
	local values = { ... }
	local total = 0
	for _, value in ipairs(values) do total += buffer.len(value) end
	local result = buffer.create(total)
	local offset = 0
	for _, value in ipairs(values) do
		local length = buffer.len(value)
		buffer.copy(result, offset, value, 0, length)
		offset += length
	end
	return result
end

local function __RLS_Ed25519VerifyBuffer(message, publicKey, signature)
	if typeof(publicKey) ~= "buffer" or buffer.len(publicKey) ~= 32
		or typeof(message) ~= "buffer"
		or typeof(signature) ~= "buffer" or buffer.len(signature) ~= 64 then
		return false
	end
	if bit32.band(buffer.readu8(signature, 63), 0xE0) ~= 0 then return false end
	local commitmentBytes = buffer.create(32)
	buffer.copy(commitmentBytes, 0, signature, 0, 32)
	local responseBytes = buffer.create(32)
	buffer.copy(responseBytes, 0, signature, 32, 32)
	if not __RLS_FieldQuadratic.IsValidScalar(responseBytes) then return false end
	local publicPoint = __RLS_Edwards25519.Decode(publicKey)
	local commitmentPoint = __RLS_Edwards25519.Decode(commitmentBytes)
	if not publicPoint or not commitmentPoint then return false end

	local challengeHash = __RLS_SHA512(__RLS_ConcatBuffers(commitmentBytes, publicKey, message))
	local challengeScalar = __RLS_FieldQuadratic.DecodeWide(challengeHash)
	local responseScalar = __RLS_FieldQuadratic.Decode(responseBytes)
	local responseBits, responseBitCount = __RLS_FieldQuadratic.Bits(responseScalar)
	local responsePoint = __RLS_Edwards25519.MulG(responseBits, responseBitCount)
	local challengeBits, challengeBitCount = __RLS_FieldQuadratic.Bits(challengeScalar)
	local challengedPublic = __RLS_Edwards25519.Mul(publicPoint, challengeBits, challengeBitCount)
	local combined = __RLS_Edwards25519.Add(commitmentPoint, __RLS_Edwards25519.Niels(challengedPublic))
	local difference = __RLS_Edwards25519.Sub(combined, __RLS_Edwards25519.Niels(responsePoint))
	difference = __RLS_Edwards25519.Double(difference)
	difference = __RLS_Edwards25519.Double(difference)
	difference = __RLS_Edwards25519.Double(difference)
	local differenceX = buffer.create(104)
	local differenceT = buffer.create(104)
	buffer.copy(differenceX, 0, difference, 0, 104)
	buffer.copy(differenceT, 0, difference, 3 * 104, 104)
	return __RLS_FieldPrime.Eqz(differenceX) and __RLS_FieldPrime.Eqz(differenceT)
end

local __RLS_PublicKeyBytes = __RLS_DecodeBase64Url(__RLS_PublicKeyBase64Url)
assert(type(__RLS_PublicKeyBytes) == "string" and #__RLS_PublicKeyBytes == 32, "invalid embedded publisher key")
local __RLS_PublicKeyBuffer = buffer.fromstring(__RLS_PublicKeyBytes)

local function __RLS_VerifyPayloadSignature(message, signature)
	if type(message) ~= "string" or type(signature) ~= "string" then return false end
	local signatureBytes = __RLS_DecodeBase64Url(signature)
	if type(signatureBytes) ~= "string" or #signatureBytes ~= 64 then return false end
	local ok, valid = pcall(
		__RLS_Ed25519VerifyBuffer,
		buffer.fromstring(message),
		__RLS_PublicKeyBuffer,
		buffer.fromstring(signatureBytes)
	)
	return ok and valid == true
end

local RolandSecurity = (function()
--!strict
-- Roland Security runtime client.
--
-- This module intentionally keeps every client detector advisory. A hostile
-- executor controls this process, so license state and punitive decisions stay
-- on the server. Client observations can pause the protected payload locally,
-- but never call an administrative blacklist endpoint.

local RolandSecurity = {}
RolandSecurity.__index = RolandSecurity

local UINT32 = 4294967296
local MAX_HTTP_RESPONSE_BYTES = 256 * 1024
local DEFAULT_DETECTOR_VERSION = "roland-client-2026.10.1"
local ABSENT_GLOBAL = {}
local DIAGNOSTIC_CONFIRMATION = "ROLAND_STAGING_DIAGNOSTICS"
local TERMINAL_ERROR_CODES = {
	SESSION_DENIED = true,
	LICENSE_DENIED = true,
	LICENSE_EXPIRED = true,
	LICENSE_REVOKED = true,
	LICENSE_BLACKLISTED = true,
}

local SIGNALS = {
	-- Local correlation scores one maximum per independent evidence family.
	-- Operational/heuristic failures are telemetry only and cannot quarantine by
	-- themselves, even when they repeat.
	L01_LOADSTRING_HOOKED = { severity = "HIGH", confidence = 70, score = 52, family = "COMPILER", decisive = true },
	L02_LOADSTRING_TAMPERED = { severity = "HIGH", confidence = 80, score = 64, family = "COMPILER", decisive = true },
	L03_CANARY_TOKEN_EXPOSED = { severity = "HIGH", confidence = 85, score = 72, family = "EXPOSURE", decisive = true },
	L04_PAYLOAD_SIGNATURE_INVALID = { severity = "HIGH", confidence = 85, score = 72, family = "PUBLISHER", decisive = true },
	L05_NATIVE_CLOSURE_INVALID = { severity = "HIGH", confidence = 70, score = 49, family = "RUNTIME_INTEGRITY", decisive = true },
	L06_TIMING_ANOMALY = { severity = "MEDIUM", confidence = 40, score = 20, family = "HEURISTIC", decisive = false },
	L07_GLOBAL_ENV_MISMATCH = { severity = "HIGH", confidence = 70, score = 49, family = "ENVIRONMENT", decisive = false },
	L08_LOADSTRING_UPVALUE_FOUND = { severity = "HIGH", confidence = 70, score = 49, family = "COMPILER", decisive = true },
	L09_LOADSTRING_SOURCE_INVALID = { severity = "HIGH", confidence = 70, score = 49, family = "COMPILER", decisive = true },
	L10_UI_ARTIFACT_FOUND = { severity = "LOW", confidence = 25, score = 6, family = "HEURISTIC", decisive = false },
	L11_HTTP_CHANNEL_HOOKED = { severity = "HIGH", confidence = 75, score = 56, family = "TRANSPORT", decisive = true },
	L12_PAYLOAD_COMPILATION_FAILED = { severity = "MEDIUM", confidence = 45, score = 20, family = "OPERATIONAL", decisive = false },
	L13_RUNTIME_EXECUTION_FAILED = { severity = "MEDIUM", confidence = 40, score = 16, family = "OPERATIONAL", decisive = false },
}

local SEVERITY_RANK = { LOW = 1, MEDIUM = 2, HIGH = 3, CRITICAL = 4 }
local QUARANTINE_REASON_PRIORITY = {
	["lease-expired"] = 1,
	["local-correlation"] = 2,
	["server-decision"] = 3,
}

local SHA256_CONSTANTS = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function add32(...)
	local total = 0
	for index = 1, select("#", ...) do
		total = (total + select(index, ...)) % UINT32
	end
	return total
end

local function sha256(message)
	assert(type(message) == "string", "sha256 expects a string")
	local messageLength = #message
	local bitLength = messageLength * 8
	local high = math.floor(bitLength / UINT32)
	local low = bitLength % UINT32
	local zeroPadding = (56 - ((messageLength + 1) % 64)) % 64
	local paddedLength = messageLength + 1 + zeroPadding + 8

	local function paddedByte(position)
		if position <= messageLength then
			return string.byte(message, position)
		elseif position == messageLength + 1 then
			return 0x80
		elseif position <= paddedLength - 8 then
			return 0
		end
		local lengthOffset = position - (paddedLength - 7)
		if lengthOffset < 4 then
			return bit32.band(bit32.rshift(high, (3 - lengthOffset) * 8), 0xff)
		end
		return bit32.band(bit32.rshift(low, (7 - lengthOffset) * 8), 0xff)
	end

	local h0, h1, h2, h3 = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local h4, h5, h6, h7 = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	local words = {}
	for offset = 1, paddedLength, 64 do
		for index = 0, 15 do
			local position = offset + index * 4
			local first, second, third, fourth
			if position + 3 <= messageLength then
				first, second, third, fourth = string.byte(message, position, position + 3)
			else
				first = paddedByte(position)
				second = paddedByte(position + 1)
				third = paddedByte(position + 2)
				fourth = paddedByte(position + 3)
			end
			words[index + 1] = add32(
				bit32.lshift(first, 24),
				bit32.lshift(second, 16),
				bit32.lshift(third, 8),
				fourth
			)
		end
		for index = 17, 64 do
			local left = words[index - 15]
			local right = words[index - 2]
			local s0 = bit32.bxor(bit32.rrotate(left, 7), bit32.rrotate(left, 18), bit32.rshift(left, 3))
			local s1 = bit32.bxor(bit32.rrotate(right, 17), bit32.rrotate(right, 19), bit32.rshift(right, 10))
			words[index] = add32(words[index - 16], s0, words[index - 7], s1)
		end

		local a, b, c, d = h0, h1, h2, h3
		local e, f, g, h = h4, h5, h6, h7
		for index = 1, 64 do
			local sum1 = bit32.bxor(bit32.rrotate(e, 6), bit32.rrotate(e, 11), bit32.rrotate(e, 25))
			local choose = bit32.bxor(bit32.band(e, f), bit32.band(bit32.bnot(e), g))
			local temp1 = add32(h, sum1, choose, SHA256_CONSTANTS[index], words[index])
			local sum0 = bit32.bxor(bit32.rrotate(a, 2), bit32.rrotate(a, 13), bit32.rrotate(a, 22))
			local majority = bit32.bxor(bit32.band(a, b), bit32.band(a, c), bit32.band(b, c))
			local temp2 = add32(sum0, majority)
			h, g, f, e, d, c, b, a = g, f, e, add32(d, temp1), c, b, a, add32(temp1, temp2)
		end

		h0, h1, h2, h3 = add32(h0, a), add32(h1, b), add32(h2, c), add32(h3, d)
		h4, h5, h6, h7 = add32(h4, e), add32(h5, f), add32(h6, g), add32(h7, h)
	end

	return string.format("%08x%08x%08x%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4, h5, h6, h7)
end

local function jsonEscape(value)
	local substitutions = {
		['"'] = '\\"',
		["\\"] = "\\\\",
		["\b"] = "\\b",
		["\f"] = "\\f",
		["\n"] = "\\n",
		["\r"] = "\\r",
		["\t"] = "\\t",
	}
	return '"' .. value:gsub('[%z\1-\31\\"]', function(character)
		return substitutions[character] or string.format("\\u%04x", string.byte(character))
	end) .. '"'
end

local function isArray(value)
	local highest = 0
	local count = 0
	for key in pairs(value) do
		if type(key) ~= "number" or key < 1 or key % 1 ~= 0 then
			return false
		end
		highest = math.max(highest, key)
		count = count + 1
	end
	return highest == count
end

local function canonicalJson(value, seen)
	local valueType = type(value)
	if value == nil then
		return "null"
	elseif valueType == "boolean" then
		return value and "true" or "false"
	elseif valueType == "number" then
		assert(value == value and value ~= math.huge and value ~= -math.huge, "non-finite number")
		return string.format("%.17g", value)
	elseif valueType == "string" then
		return jsonEscape(value)
	elseif valueType ~= "table" then
		error("unsupported canonical JSON value: " .. valueType)
	end

	seen = seen or {}
	assert(not seen[value], "cyclic table")
	seen[value] = true
	local parts = {}
	if isArray(value) then
		for index = 1, #value do
			parts[index] = canonicalJson(value[index], seen)
		end
		seen[value] = nil
		return "[" .. table.concat(parts, ",") .. "]"
	end

	local keys = {}
	for key in pairs(value) do
		assert(type(key) == "string", "object keys must be strings")
		table.insert(keys, key)
	end
	table.sort(keys)
	for index, key in ipairs(keys) do
		parts[index] = jsonEscape(key) .. ":" .. canonicalJson(value[key], seen)
	end
	seen[value] = nil
	return "{" .. table.concat(parts, ",") .. "}"
end

local function shallowCopy(source)
	local copy = {}
	for key, value in pairs(source or {}) do
		copy[key] = value
	end
	return copy
end

local function clamp(value, minimum, maximum)
	return math.max(minimum, math.min(maximum, value))
end

local function isIntegerInRange(value, minimum, maximum)
	return type(value) == "number"
		and value == value
		and value > -math.huge
		and value < math.huge
		and value == math.floor(value)
		and value >= minimum
		and value <= maximum
end

local function isUuid(value)
	return type(value) == "string"
		and value:match("^[%x][%x][%x][%x][%x][%x][%x][%x]%-[%x][%x][%x][%x]%-[1-8][%x][%x][%x]%-[89aAbB][%x][%x][%x]%-[%x][%x][%x][%x][%x][%x][%x][%x][%x][%x][%x][%x]$") ~= nil
end

local function isSessionTokenForId(token, sessionId)
	if type(token) ~= "string" or not isUuid(sessionId) or #token ~= 84 then
		return false
	end
	local tokenSessionId, secret = token:match("^RSS_([^_]+)_([%w_%-]+)$")
	return tokenSessionId ~= nil
		and tokenSessionId:lower() == sessionId:lower()
		and type(secret) == "string"
		and #secret == 43
		and secret:match("^[%w_%-]+$") ~= nil
end

local function hasValidLeaseTiming(data)
	return type(data) == "table"
		and isIntegerInRange(data.leaseRemainingSeconds, 1, 300)
		and isIntegerInRange(data.heartbeatAfterSeconds, 10, 125)
end

local function hasValidEventDecision(data)
	return type(data) == "table" and (
		(data.decision == "OBSERVE" and data.action == "NONE")
		or (data.decision == "QUARANTINE" and data.action == "DEVICE_TEMPORARILY_QUARANTINED")
	)
end

local function median(values)
	local copy = shallowCopy(values)
	table.sort(copy)
	local count = #copy
	if count == 0 then
		return 0
	elseif count % 2 == 1 then
		return copy[(count + 1) / 2]
	end
	return (copy[count / 2] + copy[count / 2 + 1]) / 2
end

local function safeCall(callback, ...)
	if type(callback) ~= "function" then
		return false, "unavailable"
	end
	return pcall(callback, ...)
end

local function safeString(value, fallback)
	local ok, result = pcall(tostring, value)
	if not ok or type(result) ~= "string" then
		return fallback or "unprintable"
	end
	return result
end

local function isSafeStorageKey(value)
	if type(value) ~= "string" or value == "" or #value > 500
		or value:match("^[%w%._@/-]+$") == nil
		or value:sub(1, 1) == "/" or value:sub(-1) == "/"
		or value:find("//", 1, true) ~= nil then
		return false
	end
	local windowsDevices = {
		CON = true, PRN = true, AUX = true, NUL = true,
		COM1 = true, COM2 = true, COM3 = true, COM4 = true, COM5 = true,
		COM6 = true, COM7 = true, COM8 = true, COM9 = true,
		LPT1 = true, LPT2 = true, LPT3 = true, LPT4 = true, LPT5 = true,
		LPT6 = true, LPT7 = true, LPT8 = true, LPT9 = true,
	}
	for segment in value:gmatch("[^/]+") do
		if segment == "." or segment == ".." or segment:sub(-1) == "." then
			return false
		end
		local deviceBase = segment:upper():match("^([^.]+)")
		if windowsDevices[deviceBase] then return false end
	end
	return true
end

local function safeRawGet(container, name)
	if type(container) ~= "table" then
		return nil
	end
	-- Executor environments often expose built-ins through a metatable rather
	-- than raw fields. Index under pcall so both layouts remain compatible.
	local ok, value = pcall(function() return container[name] end)
	return ok and value or nil
end

local function resolveEnvironment()
	local candidate = _G
	local getEnvironment = safeRawGet(_G, "getgenv")
	if type(getEnvironment) ~= "function" then
		local ok, direct = pcall(function() return getgenv end)
		if ok then getEnvironment = direct end
	end
	if type(getEnvironment) == "function" then
		local ok, result = pcall(getEnvironment)
		if ok and type(result) == "table" then
			candidate = result
		end
	end
	if candidate == _G then
		local ok, result = pcall(function() return getfenv(0) end)
		if ok and type(result) == "table" then candidate = result end
	end
	return candidate
end

local function resolveRequest(environment)
	local candidates = {}
	local function append(candidate)
		if type(candidate) == "function" then
			table.insert(candidates, candidate)
		end
	end
	append(safeRawGet(environment, "request"))
	append(safeRawGet(environment, "http_request"))
	local syn = safeRawGet(environment, "syn")
	local fluxus = safeRawGet(environment, "fluxus")
	local http = safeRawGet(environment, "http")
	append(safeRawGet(syn, "request"))
	append(safeRawGet(fluxus, "request"))
	append(safeRawGet(http, "request"))
	for _, candidate in ipairs(candidates) do
		return candidate
	end
	return nil
end

local function resolveLoadstring(environment)
	local candidate = safeRawGet(environment, "loadstring")
	if type(candidate) == "function" then
		return candidate
	end
	local globalCandidate = safeRawGet(_G, "loadstring")
	if type(globalCandidate) ~= "function" then
		local ok, direct = pcall(function() return loadstring end)
		if ok then globalCandidate = direct end
	end
	return type(globalCandidate) == "function" and globalCandidate or nil
end

local function defaultClock()
	return os.clock()
end

local function validateBaseUrl(baseUrl, allowInsecureLocalhost)
	assert(type(baseUrl) == "string" and #baseUrl > 0, "baseUrl is required")
	baseUrl = baseUrl:gsub("/+$", "")
	local scheme, authority = baseUrl:match("^(https?)://([^/%?#]+)$")
	if not scheme or not authority or authority:find("@", 1, true) or authority:find("\\", 1, true) or authority:find("%s") then
		error("baseUrl must be a bare HTTP(S) origin without credentials, path, query or fragment")
	end
	if scheme == "https" then
		return baseUrl
	end
	if allowInsecureLocalhost then
		if authority and (authority:match("^127%.0%.0%.1:%d+$") or authority == "127.0.0.1" or authority:match("^localhost:%d+$") or authority == "localhost") then
			return baseUrl
		end
	end
	error("baseUrl must use HTTPS (HTTP is allowed only for explicit localhost development)")
end

local FORBIDDEN_METADATA_PARTS = {
	"authorization", "cookie", "hwid", "key", "password", "resume", "secret", "sessiontoken", "session_token", "token",
}

local function safeMetadataKey(key)
	if type(key) ~= "string" or #key == 0 or #key > 64 then
		return false
	end
	local lowered = key:lower()
	if lowered == "__proto__" or lowered == "prototype" or lowered == "constructor" or lowered:sub(1, 8) == "_runtime" then
		return false
	end
	for _, part in ipairs(FORBIDDEN_METADATA_PARTS) do
		if lowered:find(part, 1, true) then
			return false
		end
	end
	return true
end

local function sanitizeMetadata(value, depth)
	depth = depth or 0
	if depth > 4 then
		return nil
	end
	local kind = type(value)
	if kind == "nil" or kind == "boolean" then
		return value
	elseif kind == "number" then
		return value == value and value ~= math.huge and value ~= -math.huge and value or nil
	elseif kind == "string" then
		return value:sub(1, 256)
	elseif kind ~= "table" then
		return nil
	end

	local result = {}
	local count = 0
	if isArray(value) then
		for index = 1, math.min(#value, 24) do
			local child = sanitizeMetadata(value[index], depth + 1)
			if child ~= nil then
				table.insert(result, child)
			end
		end
		return result
	end

	for key, childValue in pairs(value) do
		if count >= 24 then
			break
		end
		if safeMetadataKey(key) then
			local child = sanitizeMetadata(childValue, depth + 1)
			if child ~= nil then
				result[key] = child
				count = count + 1
			end
		end
	end
	return result
end

local function parseHttpResponse(response, jsonDecode)
	if type(response) ~= "table" then
		return 0, nil, "invalid-response", nil
	end
	local status = tonumber(response.StatusCode or response.Status or response.status_code or response.status) or 0
	local headers = response.Headers
	if type(headers) ~= "table" then headers = response.headers end
	if type(headers) ~= "table" then headers = nil end
	local body = response.Body or response.body
	if type(body) == "table" then
		return status, body, nil, headers
	elseif type(body) ~= "string" or body == "" then
		return status, nil, "empty-response", headers
	elseif #body > MAX_HTTP_RESPONSE_BYTES then
		return status, nil, "response-too-large", headers
	end
	local ok, decoded = pcall(jsonDecode, body)
	if not ok or type(decoded) ~= "table" then
		return status, nil, "invalid-json", headers
	end
	return status, decoded, nil, headers
end

local function parseRawHttpResponse(response, jsonDecode, maximumBytes)
	if type(response) ~= "table" then
		return 0, nil, nil, "invalid-response", nil
	end
	local status = tonumber(response.StatusCode or response.Status or response.status_code or response.status) or 0
	local headers = response.Headers
	if type(headers) ~= "table" then headers = response.headers end
	if type(headers) ~= "table" then headers = nil end
	local body = response.Body or response.body
	if status >= 200 and status < 300 then
		if type(body) ~= "string" or body == "" then
			return status, nil, nil, "empty-response", headers
		elseif #body > maximumBytes then
			return status, nil, nil, "response-too-large", headers
		end
		return status, body, nil, nil, headers
	end
	if type(body) == "table" then
		return status, nil, body, nil, headers
	elseif type(body) ~= "string" or body == "" then
		return status, nil, nil, "empty-response", headers
	elseif #body > MAX_HTTP_RESPONSE_BYTES then
		return status, nil, nil, "response-too-large", headers
	end
	local ok, decoded = pcall(jsonDecode, body)
	if not ok or type(decoded) ~= "table" then
		return status, nil, nil, "invalid-json", headers
	end
	return status, nil, decoded, nil, headers
end

local function headerValue(headers, expectedName)
	if type(headers) ~= "table" then return nil end
	local wanted = expectedName:lower()
	for key, value in pairs(headers) do
		if type(key) == "string" and key:lower() == wanted then
			if type(value) == "table" then value = value[1] end
			return type(value) == "string" and value or nil
		end
	end
	return nil
end

local function retryAfterSeconds(headers, maximum)
	if type(headers) ~= "table" then return nil end
	for key, value in pairs(headers) do
		if type(key) == "string" and key:lower() == "retry-after" then
			if type(value) == "table" then value = value[1] end
			local seconds = tonumber(value)
			if seconds and seconds == seconds and seconds >= 0 and seconds < math.huge then
				return clamp(seconds, 0.25, maximum or 30)
			end
		end
	end
	return nil
end

local function responseErrorCode(data)
	if type(data) ~= "table" or type(data.error) ~= "table" then
		return nil
	end
	return type(data.error.code) == "string" and data.error.code or nil
end

local function defaultAdapters(environment)
	local gameObject = safeRawGet(environment, "game") or safeRawGet(_G, "game")
	if gameObject == nil then
		local ok, direct = pcall(function() return game end)
		if ok then gameObject = direct end
	end
	local httpService
	if gameObject ~= nil then
		local ok, service = pcall(function()
			return gameObject:GetService("HttpService")
		end)
		if ok then
			httpService = service
		end
	end
	return {
		request = resolveRequest(environment),
		clock = defaultClock,
		wait = function(seconds)
			local taskLibrary = safeRawGet(environment, "task") or safeRawGet(_G, "task")
			if taskLibrary == nil then
				local ok, direct = pcall(function() return task end)
				if ok then taskLibrary = direct end
			end
			assert(type(taskLibrary) == "table" and type(taskLibrary.wait) == "function", "task.wait is unavailable")
			return taskLibrary.wait(seconds)
		end,
		spawn = function(callback)
			local taskLibrary = safeRawGet(environment, "task") or safeRawGet(_G, "task")
			if taskLibrary == nil then
				local ok, direct = pcall(function() return task end)
				if ok then taskLibrary = direct end
			end
			assert(type(taskLibrary) == "table" and type(taskLibrary.spawn) == "function", "task.spawn is unavailable")
			return taskLibrary.spawn(callback)
		end,
		nowIso = function()
			local dateTime = safeRawGet(environment, "DateTime") or safeRawGet(_G, "DateTime")
			if dateTime == nil then
				local ok, direct = pcall(function() return DateTime end)
				if ok then dateTime = direct end
			end
			if type(dateTime) == "table" and type(dateTime.now) == "function" then
				local ok, result = pcall(function()
					return dateTime.now():ToIsoDate()
				end)
				if ok then return result end
			end
			return os.date("!%Y-%m-%dT%H:%M:%SZ")
		end,
		jsonEncode = httpService and function(value) return httpService:JSONEncode(value) end or nil,
		jsonDecode = httpService and function(value) return httpService:JSONDecode(value) end or nil,
		uuid = httpService and function() return httpService:GenerateGUID(false) end or nil,
	}
end

local function discoverExecutorName(environment)
	for _, name in ipairs({ "identifyexecutor", "getexecutorname" }) do
		local callback = safeRawGet(environment, name)
		if type(callback) == "function" then
			local ok, first = pcall(callback)
			if ok and first ~= nil then
				return safeString(first, "unknown"):sub(1, 64)
			end
		end
	end
	return nil
end

local function discoverHwid(environment)
	for _, name in ipairs({ "gethwid", "get_hwid" }) do
		local callback = safeRawGet(environment, name)
		if type(callback) == "function" then
			local ok, value = pcall(callback)
			if ok and type(value) == "string" and #value >= 8 then
				return value
			end
		end
	end
	return nil
end

local function joinPath(baseUrl, path)
	return baseUrl .. path
end

function RolandSecurity.new(config)
	assert(type(config) == "table", "config table is required")
	assert(type(config.key) == "string" and #config.key > 0, "config.key is required")
	assert(type(config.clientVersion) == "string" and #config.clientVersion > 0, "config.clientVersion is required")

	local environment = config.environment or resolveEnvironment()
	local defaults = defaultAdapters(environment)
	local suppliedAdapters = config.adapters or {}
	local adapters = {}
	for key, value in pairs(defaults) do
		adapters[key] = value
	end
	for key, value in pairs(suppliedAdapters) do
		adapters[key] = value
	end
	for _, name in ipairs({ "request", "clock", "wait", "spawn", "nowIso", "jsonEncode", "jsonDecode", "uuid" }) do
		assert(type(adapters[name]) == "function", "missing adapter: " .. name)
	end

	local self = setmetatable({}, RolandSecurity)
	self._environment = environment
	self._adapters = adapters
	self._baseUrl = validateBaseUrl(config.baseUrl, config.allowInsecureLocalhost == true)
	self._licenseKey = config.key
	self._clientVersion = config.clientVersion:sub(1, 64)
	assert(config.detectorVersion == nil or type(config.detectorVersion) == "string", "detectorVersion must be a string")
	self._detectorVersion = (config.detectorVersion or DEFAULT_DETECTOR_VERSION):sub(1, 64)
	self._mode = config.mode == "quarantine" and "quarantine" or "observe"
	self._manualScheduling = config.manualScheduling == true
	for _, name in ipairs({ "callbacks", "detectors", "payloadPolicy", "quarantine", "queue", "activation", "leaseWatchdog" }) do
		assert(config[name] == nil or type(config[name]) == "table", name .. " must be a table")
	end
	self._callbacks = config.callbacks or {}
	self._detectorConfig = config.detectors or {}
	self._payloadPolicy = config.payloadPolicy or {}
	self._quarantineConfig = config.quarantine or {}
	self._queueConfig = config.queue or {}
	self._activationConfig = config.activation or {}
	self._leaseConfig = config.leaseWatchdog or {}
	self._diagnosticEnabled = config.deployment == "staging"
		and type(config.diagnostics) == "table"
		and config.diagnostics.enabled == true
		and config.diagnostics.confirmation == DIAGNOSTIC_CONFIRMATION
	self._allowUnsignedPayload = self._diagnosticEnabled and self._payloadPolicy.allowUnsigned == true
	self._state = "CREATED"
	self._sessionId = nil
	self._sessionToken = nil
	self._authorizedBuildId = nil
	self._authorizedBuild = nil
	self._resumeToken = config.resumeToken
	self._clientInstanceId = self._detectorConfig.clientInstanceId or self._adapters.uuid()
	self._activationId = self._activationConfig.activationId or self._adapters.uuid()
	assert(type(self._clientInstanceId) == "string" and #self._clientInstanceId >= 1 and #self._clientInstanceId <= 128,
		"clientInstanceId must be a 1-128 character string")
	assert(self._clientInstanceId:match("^[%w%._:@/%-]+$") ~= nil,
		"clientInstanceId contains unsupported characters")
	assert(type(self._activationId) == "string"
		and self._activationId:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$") ~= nil,
		"activationId must be a UUID")
	self._activationId = self._activationId:lower()
	self._heartbeatSequence = nil
	self._heartbeatAfter = 24
	self._heartbeatDueAt = math.huge
	self._leaseDeadlineAt = math.huge
	self._requestBusy = false
	self._stopping = false
	self._eventQueue = {}
	self._sentAt = {}
	self._dedupUntil = {}
	self._dedupCount = 0
	self._lastDedupPrune = 0
	self._riskObservations = {}
	self._chainIndex = 0
	self._chainDigest = string.rep("0", 64)
	self._droppedEvents = 0
	self._lastErrorCode = nil
	self._quarantined = false
	self._quarantineReason = nil
	self._quarantineCauses = {}
	self._protectedPayloadStarted = false
	local environmentRequest = resolveRequest(environment)
	local environmentLoadstring = resolveLoadstring(environment)
	self._captured = {
		-- Transport/compiler adapters may deliberately wrap executor primitives.
		-- Detector identity baselines therefore capture the environment itself,
		-- while operational calls use the configured adapters below.
		requestIdentity = environmentRequest,
		loadstringIdentity = environmentLoadstring,
		loadstring = config.loadstring or environmentLoadstring,
		globals = {},
	}
	for _, name in ipairs(self._detectorConfig.globalNames or { "loadstring", "request", "http_request" }) do
		self._captured.globals[name] = safeRawGet(environment, name) or ABSENT_GLOBAL
	end
	return self
end

function RolandSecurity:_notify(name, ...)
	local callback = self._callbacks[name]
	if type(callback) == "function" then
		local ok = pcall(callback, ...)
		return ok
	end
	return false
end

function RolandSecurity:_acquireRequestLock(timeoutSeconds)
	local deadline = self._adapters.clock() + (timeoutSeconds or 5)
	while self._requestBusy and self._adapters.clock() < deadline do
		self._adapters.wait(0.025)
	end
	if self._requestBusy then
		return false
	end
	self._requestBusy = true
	return true
end

function RolandSecurity:_post(path, body, authenticated)
	if not self:_acquireRequestLock(5) then
		return 0, nil, "client-request-busy"
	end
	local headers = { ["Content-Type"] = "application/json", Accept = "application/json" }
	if authenticated then
		if not self._sessionToken then
			self._requestBusy = false
			return 0, nil, "missing-session"
		end
		headers.Authorization = "Bearer " .. self._sessionToken
	end
	local encodeOk, encoded = pcall(self._adapters.jsonEncode, body)
	if not encodeOk then
		self._requestBusy = false
		return 0, nil, "encode-failed"
	end
	local requestOk, response = pcall(self._adapters.request, {
		Url = joinPath(self._baseUrl, path),
		Method = "POST",
		Headers = headers,
		Body = encoded,
	})
	self._requestBusy = false
	if not requestOk then
		return 0, nil, "network-failed"
	end
	return parseHttpResponse(response, self._adapters.jsonDecode)
end

function RolandSecurity:_getPayload(path)
	if not self:_acquireRequestLock(5) then
		return 0, nil, nil, "client-request-busy", nil
	end
	if not self._sessionToken then
		self._requestBusy = false
		return 0, nil, nil, "missing-session", nil
	end
	local maximumBytes = clamp(
		math.floor(tonumber(self._payloadPolicy.maximumBytes) or 1048576),
		65536,
		4194304
	)
	local requestOk, response = pcall(self._adapters.request, {
		Url = joinPath(self._baseUrl, path),
		Method = "GET",
		Headers = {
			Accept = "text/plain",
			Authorization = "Bearer " .. self._sessionToken,
		},
	})
	self._requestBusy = false
	if not requestOk then
		return 0, nil, nil, "network-failed", nil
	end
	return parseRawHttpResponse(response, self._adapters.jsonDecode, maximumBytes)
end

function RolandSecurity:_activationIdentity()
	local config = self._detectorConfig
	local hwid = type(config.getHwid) == "function" and select(2, safeCall(config.getHwid)) or nil
	hwid = type(hwid) == "string" and hwid or discoverHwid(self._environment)
	assert(type(hwid) == "string" and #hwid >= 8 and #hwid <= 512, "No valid HWID provider is available; configure detectors.getHwid")

	local executorName = type(config.executorName) == "string" and config.executorName or discoverExecutorName(self._environment)
	local robloxUserId = config.robloxUserId
	local serverJobId = config.serverJobId
	local gameObject = safeRawGet(self._environment, "game") or safeRawGet(_G, "game")
	if gameObject == nil then
		local ok, direct = pcall(function() return game end)
		if ok then gameObject = direct end
	end
	if gameObject ~= nil then
		if robloxUserId == nil then
			pcall(function()
				local players = gameObject:GetService("Players")
				if players.LocalPlayer then
					robloxUserId = tostring(players.LocalPlayer.UserId)
				end
			end)
		end
		if serverJobId == nil then
			pcall(function()
				if type(gameObject.JobId) == "string" and gameObject.JobId ~= "" then
					serverJobId = gameObject.JobId
				end
			end)
		end
	end
	return hwid, executorName, robloxUserId, serverJobId
end

function RolandSecurity:_rejectAcceptedActivation(data, status, code)
	-- If the server created a valid session but its response violates the local
	-- build/policy contract, best-effort close it instead of leaking a tab slot.
	if type(data) == "table" and isSessionTokenForId(data.sessionToken, data.sessionId) then
		self._sessionToken = data.sessionToken
		self:_post("/v1/runtime/deactivate", {}, true)
	end
	self._sessionToken = nil
	self._state = "DENIED"
	self._lastErrorCode = code
	self:_notify("onDenied", code, status)
	return false, code
end

function RolandSecurity:_validateAuthorizedBuild(data)
	local configuredBuildId = self._payloadPolicy.buildId
	if configuredBuildId ~= nil and not isUuid(configuredBuildId) then
		return nil, "INVALID_PAYLOAD_POLICY"
	end
	if data.buildId == nil then
		if data.build ~= nil then return nil, "INVALID_ACTIVATION_RESPONSE" end
		if self._payloadPolicy.publisherKeyId ~= nil or self._payloadPolicy.productCode ~= nil
			or self._payloadPolicy.buildId ~= nil then
			return nil, "BUILD_AUTHORIZATION_MISMATCH"
		end
		return nil, nil
	end
	if not isUuid(data.buildId) then
		return nil, "INVALID_ACTIVATION_RESPONSE"
	end
	if configuredBuildId ~= nil and configuredBuildId ~= data.buildId then
		return nil, "BUILD_AUTHORIZATION_MISMATCH"
	end
	if type(data.build) ~= "table" then
		return nil, "INVALID_ACTIVATION_RESPONSE"
	end
	local build = data.build
	local configuredAlgorithm = self._payloadPolicy.algorithm
	if configuredAlgorithm ~= nil and configuredAlgorithm ~= "Ed25519" then
		return nil, "INVALID_PAYLOAD_POLICY"
	end
	local expectedAlgorithm = "Ed25519"
	local expectedKeyId = self._payloadPolicy.publisherKeyId
	local expectedProduct = self._payloadPolicy.productCode
	if type(expectedKeyId) ~= "string" or expectedKeyId == ""
		or type(expectedProduct) ~= "string" or expectedProduct == "" then
		return nil, "INVALID_PAYLOAD_POLICY"
	end
	if build.buildId ~= data.buildId
		or build.version ~= self._clientVersion
		or build.algorithm ~= expectedAlgorithm
		or build.publisherKeyId ~= expectedKeyId
		or build.productCode ~= expectedProduct
		or type(build.sha256) ~= "string" or #build.sha256 ~= 64 or build.sha256:match("^[a-fA-F0-9]+$") == nil
		or type(build.signature) ~= "string" or #build.signature ~= 86 or build.signature:match("^[%w_-]+$") == nil
		or not isSafeStorageKey(build.storageKey) then
		return nil, "BUILD_AUTHORIZATION_MISMATCH"
	end
	return {
		buildId = build.buildId,
		version = build.version,
		sha256 = build.sha256:lower(),
		algorithm = build.algorithm,
		publisherKeyId = build.publisherKeyId,
		productCode = build.productCode,
		signature = build.signature,
		storageKey = build.storageKey,
	}, nil
end

function RolandSecurity:activate()
	if self._state == "ACTIVE" or self._state == "QUARANTINED" then
		return true
	end
	assert(self._state == "CREATED", "runtime cannot activate from state " .. self._state)
	self._state = "ACTIVATING"
	local maximumStartupJitter = clamp(tonumber(self._activationConfig.startupJitterSeconds) or 0, 0, 10)
	if maximumStartupJitter > 0 then
		local bucket = tonumber(sha256(self._activationId):sub(1, 8), 16) or 0
		self._adapters.wait((bucket / 0xffffffff) * maximumStartupJitter)
	end
	local hwid, executorName, robloxUserId, serverJobId = self:_activationIdentity()
	local body = {
		key = self._licenseKey,
		hwid = hwid,
		activationId = self._activationId,
		clientInstanceId = self._clientInstanceId,
		clientVersion = self._clientVersion,
	}
	if executorName then
		local cleanExecutorName = safeString(executorName, "unknown"):gsub("%c", ""):sub(1, 64)
		if cleanExecutorName ~= "" then body.executorName = cleanExecutorName end
	end
	if robloxUserId then body.robloxUserId = safeString(robloxUserId, ""):sub(1, 32) end
	if serverJobId then body.serverJobId = safeString(serverJobId, ""):sub(1, 64) end
	local resumedActivation = self._resumeToken ~= nil
	if self._resumeToken then body.resumeToken = self._resumeToken end

	local status, data, transportError, responseHeaders = 0, nil, nil, nil
	local maximumAttempts = clamp(math.floor(tonumber(self._activationConfig.maxAttempts) or 3), 1, 5)
	for attempt = 1, maximumAttempts do
		status, data, transportError, responseHeaders = self:_post("/v1/runtime/activate", body, false)
		local accepted = (status == 200 or status == 201)
			and type(data) == "table"
			and data.activationId == self._activationId
			and isSessionTokenForId(data.sessionToken, data.sessionId)
			and isIntegerInRange(data.nextHeartbeatSequence, 1, 2147483647)
			and (resumedActivation or data.nextHeartbeatSequence == 1)
			and hasValidLeaseTiming(data)
		if accepted then
			break
		end
		local retryable = status == 0 or status == 429 or status >= 500
			or (status == 200 or status == 201)
		if not retryable or attempt == maximumAttempts then
			break
		end
		local baseDelay = clamp(tonumber(self._activationConfig.retryBaseSeconds) or 0.25, 0.05, 2)
		local delay = status == 429 and retryAfterSeconds(responseHeaders, 30)
			or math.min(2, baseDelay * (2 ^ (attempt - 1)))
		self._adapters.wait(delay)
	end
	self._licenseKey = nil
	self._resumeToken = nil
	if status ~= 200 and status ~= 201 then
		self._state = "DENIED"
		self._lastErrorCode = responseErrorCode(data) or transportError or "ACTIVATION_FAILED"
		self:_notify("onDenied", self._lastErrorCode, status)
		return false, self._lastErrorCode
	end
	if type(data) ~= "table" or data.activationId ~= self._activationId
		or not isSessionTokenForId(data.sessionToken, data.sessionId)
		or not isIntegerInRange(data.nextHeartbeatSequence, 1, 2147483647)
		or (not resumedActivation and data.nextHeartbeatSequence ~= 1)
		or not hasValidLeaseTiming(data) then
		return self:_rejectAcceptedActivation(data, status, "INVALID_ACTIVATION_RESPONSE")
	end
	local authorizedBuild, buildError = self:_validateAuthorizedBuild(data)
	if buildError then
		return self:_rejectAcceptedActivation(data, status, buildError)
	end

	self._sessionId = data.sessionId
	self._sessionToken = data.sessionToken
	self._authorizedBuildId = data.buildId or self._payloadPolicy.buildId
	self._authorizedBuild = authorizedBuild
	self._heartbeatSequence = data.nextHeartbeatSequence
	self._heartbeatAfter = clamp(tonumber(data.heartbeatAfterSeconds) or 24, 10, 125)
	self._heartbeatDueAt = self._adapters.clock() + self._heartbeatAfter
	self:_updateLease(data, false)
	self._state = "ACTIVE"
	self:_notify("onActivated", {
		sessionId = data.sessionId,
		deviceAlias = data.deviceAlias,
		leaseExpiresAt = data.leaseExpiresAt,
		buildId = self._authorizedBuildId,
		build = self._authorizedBuild and shallowCopy(self._authorizedBuild) or nil,
	})
	return true
end

function RolandSecurity:_handleTerminal(code, status)
	if self._stopping or self._state == "STOPPED" then
		return
	end
	self._lastErrorCode = code or "SESSION_TERMINATED"
	self._state = "DENIED"
	self._stopping = true
	self._sessionToken = nil
	self:_notify("onServerStop", self._lastErrorCode, status)
end

function RolandSecurity:_applyServerDecision(data)
	if type(data) ~= "table" then
		return
	end
	local action = type(data.action) == "string" and data.action:upper() or "NONE"
	local decision = type(data.decision) == "string" and data.decision:upper() or "OBSERVED"
	if action == "QUARANTINE" or action == "DEVICE_TEMPORARILY_QUARANTINED"
		or decision == "QUARANTINE" or decision == "QUARANTINED" then
		self:_quarantine("server-decision")
	elseif action == "KICK" or action == "TERMINATE" or action == "REVOKE" or action == "BLACKLIST" then
		self:_handleTerminal("SERVER_" .. action, 200)
	end
end

function RolandSecurity:_updateLease(data, allowCompatibilityFallback)
	local remaining = type(data) == "table" and tonumber(data.leaseRemainingSeconds) or nil
	if remaining == nil then
		if not allowCompatibilityFallback then
			return false
		end
		-- Compatibility fallback for an older backend. The current API returns an
		-- explicit remaining duration, avoiding wall-clock/ISO parsing on clients.
		remaining = math.max(30, self._heartbeatAfter * 3)
	end
	remaining = clamp(remaining, 0, 300)
	local now = self._adapters.clock()
	self._leaseDeadlineAt = now + remaining
	-- A retried activation can legitimately return an older, shorter lease.
	-- Never leave the first heartbeat scheduled beyond half of what remains.
	local safeHeartbeatDelay = math.max(0.25, remaining / 2)
	self._heartbeatDueAt = math.min(self._heartbeatDueAt, now + safeHeartbeatDelay)
	return true
end

function RolandSecurity:_recoverLeaseQuarantine()
	if not self._quarantined or not self._quarantineCauses["lease-expired"] or self._stopping then
		return false
	end
	self._quarantineCauses["lease-expired"] = nil
	if self._lastErrorCode == "LOCAL_LEASE_EXPIRED" then
		self._lastErrorCode = nil
	end
	local strongestReason = nil
	local strongestPriority = -1
	for reason in pairs(self._quarantineCauses) do
		local priority = QUARANTINE_REASON_PRIORITY[reason] or 2
		if priority > strongestPriority then
			strongestReason = reason
			strongestPriority = priority
		end
	end
	if strongestReason then
		self._quarantineReason = strongestReason
		return false
	end
	self._quarantined = false
	self._quarantineReason = nil
	self._state = "ACTIVE"
	self:_notify("onLeaseRecovered")
	return true
end

function RolandSecurity:_checkLeaseWatchdog()
	if self._state ~= "ACTIVE" and self._state ~= "QUARANTINED" then
		return false
	end
	local grace = clamp(tonumber(self._leaseConfig.graceSeconds) or 3, 0, 30)
	if self._adapters.clock() < self._leaseDeadlineAt + grace then
		return true
	end
	if self._lastErrorCode ~= "LOCAL_LEASE_EXPIRED" then
		self._lastErrorCode = "LOCAL_LEASE_EXPIRED"
		self:_quarantine("lease-expired")
		self:_notify("onLeaseExpired")
	end
	return false
end

function RolandSecurity:heartbeatOnce()
	if (self._state ~= "ACTIVE" and self._state ~= "QUARANTINED") or not self._heartbeatSequence then
		return false, "not-active"
	end
	local sequence = self._heartbeatSequence
	local status, data, transportError, responseHeaders = self:_post("/v1/runtime/heartbeat", { sequence = sequence }, true)
	if status == 200 and type(data) == "table"
		and data.sessionId == self._sessionId
		and isIntegerInRange(data.nextHeartbeatSequence, 1, 2147483647)
		and data.nextHeartbeatSequence == sequence + 1
		and hasValidLeaseTiming(data) then
		self._heartbeatSequence = data.nextHeartbeatSequence
		self._heartbeatAfter = data.heartbeatAfterSeconds
		self._heartbeatDueAt = self._adapters.clock() + self._heartbeatAfter
		self:_updateLease(data, false)
		self:_recoverLeaseQuarantine()
		return true, data.duplicate == true and "duplicate" or "accepted"
	end

	local code = responseErrorCode(data)
	if status == 401 or status == 403 or TERMINAL_ERROR_CODES[code] then
		self:_handleTerminal(code or "SESSION_DENIED", status)
		return false, code or "SESSION_DENIED"
	end
	local retryDelay = status == 429 and retryAfterSeconds(responseHeaders, 30)
		or math.min(5, math.max(1, self._heartbeatAfter / 4))
	self._heartbeatDueAt = self._adapters.clock() + retryDelay
	self:_checkLeaseWatchdog()
	return false, code or transportError or "HEARTBEAT_FAILED"
end

function RolandSecurity:_canSendEvent()
	local now = self._adapters.clock()
	local perMinute = clamp(tonumber(self._queueConfig.maxEventsPerMinute) or 12, 1, 120)
	while #self._sentAt > 0 and self._sentAt[1] <= now - 60 do
		table.remove(self._sentAt, 1)
	end
	return #self._sentAt < perMinute
end

function RolandSecurity:_rememberSent()
	table.insert(self._sentAt, self._adapters.clock())
end

function RolandSecurity:_enqueue(event)
	local maximum = clamp(tonumber(self._queueConfig.maxQueuedEvents) or 48, 8, 128)
	if #self._eventQueue < maximum then
		table.insert(self._eventQueue, event)
		return true
	end

	local candidateIndex = nil
	local candidateRank = 999
	for index, queued in ipairs(self._eventQueue) do
		local rank = SEVERITY_RANK[queued.body.severity] or 1
		if rank < candidateRank then
			candidateIndex = index
			candidateRank = rank
		end
	end
	local newRank = SEVERITY_RANK[event.body.severity] or 1
	if candidateIndex and newRank > candidateRank then
		table.remove(self._eventQueue, candidateIndex)
		table.insert(self._eventQueue, event)
	else
		self._droppedEvents = self._droppedEvents + 1
		return false
	end
	self._droppedEvents = self._droppedEvents + 1
	return true
end

function RolandSecurity:_recordRisk(signalCode, score, familyOverride)
	local now = self._adapters.clock()
	local window = clamp(tonumber(self._quarantineConfig.windowSeconds) or 120, 30, 900)
	local policy = SIGNALS[signalCode]
	table.insert(self._riskObservations, {
		signalCode = signalCode,
		family = familyOverride or policy.family,
		decisive = policy.decisive == true,
		score = score,
		at = now,
	})
	while #self._riskObservations > 0 and self._riskObservations[1].at < now - window do
		table.remove(self._riskObservations, 1)
	end
	while #self._riskObservations > 128 do
		table.remove(self._riskObservations, 1)
	end
	if self._mode ~= "quarantine" or self._quarantined then
		return
	end
	local familyMaximums = {}
	local decisiveFamilies = {}
	for _, observation in ipairs(self._riskObservations) do
		familyMaximums[observation.family] = math.max(familyMaximums[observation.family] or 0, observation.score)
		if observation.decisive then
			decisiveFamilies[observation.family] = true
		end
	end
	local decisiveCount = 0
	for _ in pairs(decisiveFamilies) do decisiveCount = decisiveCount + 1 end
	local total = 0
	for _, familyScore in pairs(familyMaximums) do total = total + familyScore end
	local minimumDistinct = clamp(tonumber(self._quarantineConfig.minimumDistinctFamilies)
		or tonumber(self._quarantineConfig.minimumDistinctSignals) or 2, 2, 8)
	local minimumScore = clamp(tonumber(self._quarantineConfig.minimumScore) or 100, 40, 500)
	if decisiveCount >= minimumDistinct and total >= minimumScore then
		self:_quarantine("local-correlation")
	end
end

function RolandSecurity:_quarantine(reason)
	if self._state == "DENIED" or self._state == "STOPPED" then
		return
	end
	reason = type(reason) == "string" and reason or "local-correlation"
	local alreadyRecorded = self._quarantineCauses[reason] == true
	self._quarantineCauses[reason] = true
	local currentPriority = QUARANTINE_REASON_PRIORITY[self._quarantineReason] or -1
	local newPriority = QUARANTINE_REASON_PRIORITY[reason] or 2
	if self._quarantined then
		if newPriority > currentPriority then
			self._quarantineReason = reason
			self:_notify("onQuarantine", reason)
		end
		return
	end
	self._quarantined = true
	self._quarantineReason = reason
	self._state = "QUARANTINED"
	if not alreadyRecorded then
		self:_notify("onQuarantine", reason)
	end
end

function RolandSecurity:reportSignal(signalCode, metadata, overrides)
	local policy = SIGNALS[signalCode]
	if not policy then
		return false, "unknown-signal"
	end
	if self._state ~= "ACTIVE" and self._state ~= "QUARANTINED" then
		return false, "not-active"
	end
	overrides = overrides or {}
	local cleanMetadata = sanitizeMetadata(metadata or {}) or {}
	local now = self._adapters.clock()
	local observationDigest = sha256(canonicalJson({ code = signalCode, metadata = cleanMetadata }))
	local cooldown = clamp(tonumber(self._queueConfig.dedupSeconds) or 60, 5, 600)
	if now - self._lastDedupPrune >= cooldown then
		for key, expiresAt in pairs(self._dedupUntil) do
			if expiresAt <= now then
				self._dedupUntil[key] = nil
				self._dedupCount = math.max(0, self._dedupCount - 1)
			end
		end
		self._lastDedupPrune = now
	end
	local dedupKey = signalCode .. ":" .. observationDigest
	if (self._dedupUntil[dedupKey] or 0) > now then
		return false, "duplicate-suppressed"
	end
	if self._dedupUntil[dedupKey] == nil then
		local maximumDedupEntries = clamp(math.floor(tonumber(self._queueConfig.maxDedupEntries) or 256), 64, 512)
		while self._dedupCount >= maximumDedupEntries do
			local oldestKey = nil
			local oldestExpiry = math.huge
			for candidateKey, expiresAt in pairs(self._dedupUntil) do
				if expiresAt < oldestExpiry then
					oldestKey = candidateKey
					oldestExpiry = expiresAt
				end
			end
			if oldestKey == nil then
				self._dedupCount = 0
				break
			end
			self._dedupUntil[oldestKey] = nil
			self._dedupCount = self._dedupCount - 1
		end
		self._dedupCount = self._dedupCount + 1
	end
	self._dedupUntil[dedupKey] = now + cooldown
	local evidenceMaterial = canonicalJson({
		code = signalCode,
		metadata = cleanMetadata,
		previous = self._chainDigest,
		index = self._chainIndex + 1,
	})
	local evidenceDigest = sha256(evidenceMaterial)

	self._chainIndex = self._chainIndex + 1
	cleanMetadata.chainIndex = self._chainIndex
	cleanMetadata.chainPrevious = self._chainDigest
	cleanMetadata.runtimeMode = self._mode
	self._chainDigest = evidenceDigest
	local event = {
		body = {
			eventId = self._adapters.uuid(),
			signalCode = signalCode,
			detectorVersion = self._detectorVersion,
			severity = overrides.severity or policy.severity,
			confidence = clamp(math.floor(tonumber(overrides.confidence) or policy.confidence), 0, 100),
			evidenceDigest = evidenceDigest,
			metadata = cleanMetadata,
			occurredAt = self._adapters.nowIso(),
		},
		attempts = 0,
		nextAttemptAt = now,
	}
	local queued = self:_enqueue(event)
	local riskFamily = nil
	if signalCode == "L07_GLOBAL_ENV_MISMATCH"
		and (overrides.riskFamily == "COMPILER" or overrides.riskFamily == "TRANSPORT") then
		riskFamily = overrides.riskFamily
	end
	self:_recordRisk(signalCode, policy.score * event.body.confidence / math.max(1, policy.confidence), riskFamily)
	self:_notify("onSignal", signalCode, cleanMetadata, queued)
	return queued, queued and event.body.eventId or "queue-full"
end

function RolandSecurity:flushEvents(maximum)
	if self._state ~= "ACTIVE" and self._state ~= "QUARANTINED" then
		return 0
	end
	if self._adapters.clock() >= self._heartbeatDueAt - 2 then
		return 0
	end
	maximum = clamp(tonumber(maximum) or tonumber(self._queueConfig.flushBurst) or 3, 1, 10)
	local sent = 0
	local index = 1
	while index <= #self._eventQueue and sent < maximum and self:_canSendEvent() do
		local queued = self._eventQueue[index]
		local now = self._adapters.clock()
		if queued.nextAttemptAt > now then
			index = index + 1
		else
			local status, data, transportError, responseHeaders = self:_post("/v1/runtime/events", queued.body, true)
			local acceptedResponse = (status == 200 or status == 202)
				and type(data) == "table"
				and data.eventId == queued.body.eventId
				and data.accepted == true
				and type(data.replayed) == "boolean"
				and ((status == 200 and data.replayed) or (status == 202 and not data.replayed))
				and hasValidLeaseTiming(data)
				and hasValidEventDecision(data)
			if acceptedResponse then
				table.remove(self._eventQueue, index)
				self:_rememberSent()
				sent = sent + 1
				self:_updateLease(data, false)
				self:_applyServerDecision(data)
			elseif status == 401 or status == 403 or TERMINAL_ERROR_CODES[responseErrorCode(data)] then
				self:_handleTerminal(responseErrorCode(data) or "SESSION_DENIED", status)
				break
			elseif status >= 400 and status < 500 and status ~= 429 then
				table.remove(self._eventQueue, index)
				self:_notify("onTelemetryDrop", responseErrorCode(data) or transportError or "rejected", queued.body.signalCode)
			else
				queued.attempts = queued.attempts + 1
				local retryDelay = status == 429 and retryAfterSeconds(responseHeaders, 30)
					or math.min(30, 2 ^ math.min(queued.attempts, 5))
				queued.nextAttemptAt = now + retryDelay
				index = index + 1
			end
		end
	end
	return sent
end

function RolandSecurity:_heartbeatLoop()
	while not self._stopping and (self._state == "ACTIVE" or self._state == "QUARANTINED") do
		local leaseValid = self:_checkLeaseWatchdog()
		local nextWake = self._heartbeatDueAt
		if leaseValid then
			local grace = clamp(tonumber(self._leaseConfig.graceSeconds) or 3, 0, 30)
			nextWake = math.min(nextWake, self._leaseDeadlineAt + grace)
		end
		local delay = math.max(0.25, nextWake - self._adapters.clock())
		self._adapters.wait(delay)
		self:_checkLeaseWatchdog()
		if not self._stopping and self._adapters.clock() >= self._heartbeatDueAt then
			self:heartbeatOnce()
		end
	end
end

function RolandSecurity:_telemetryLoop()
	local interval = clamp(tonumber(self._queueConfig.flushIntervalSeconds) or 4, 1, 30)
	while not self._stopping and (self._state == "ACTIVE" or self._state == "QUARANTINED") do
		self._adapters.wait(interval)
		if not self._stopping then
			self:flushEvents()
		end
	end
end

function RolandSecurity:_startLoops()
	if self._manualScheduling then
		return
	end
	self._adapters.spawn(function() self:_heartbeatLoop() end)
	self._adapters.spawn(function() self:_telemetryLoop() end)
end

function RolandSecurity:_checkLoadstringHook()
	local current = resolveLoadstring(self._environment)
	local identityChanged = self._captured.loadstringIdentity ~= nil and current ~= self._captured.loadstringIdentity
	local isFunctionHooked = safeRawGet(self._environment, "isfunctionhooked")
	local positive = identityChanged
	local method = identityChanged and "identity-change" or nil
	if type(isFunctionHooked) == "function" and type(current) == "function" then
		local ok, hooked = pcall(isFunctionHooked, current)
		if ok and hooked == true then
			positive = true
			method = "executor-introspection"
		end
	end
	if positive then
		self:reportSignal("L01_LOADSTRING_HOOKED", { variant = method or "unknown" })
	end
end

function RolandSecurity:_checkLoadstringCanary()
	local compiler = self._captured.loadstring
	if type(compiler) ~= "function" then
		return
	end
	local okCompile, compiled = pcall(compiler, "return (7919 * 13) + 17", "=roland-canary")
	if not okCompile or type(compiled) ~= "function" then
		self:reportSignal("L02_LOADSTRING_TAMPERED", { variant = "canary-compile" })
		return
	end
	local okRun, result = pcall(compiled)
	if not okRun or result ~= 102964 then
		self:reportSignal("L02_LOADSTRING_TAMPERED", { variant = "canary-result", resultType = type(result) })
	end
end

function RolandSecurity:_checkCanaryExposure()
	local probe = self._detectorConfig.canaryProbe
	if type(probe) ~= "function" then
		return
	end
	local canary = "RC_" .. sha256(self._adapters.uuid()):sub(1, 24)
	local ok, exposed, variant = pcall(probe, canary)
	if ok and exposed == true then
		self:reportSignal("L03_CANARY_TOKEN_EXPOSED", { variant = safeString(variant or "custom-probe", "custom-probe"):sub(1, 64) })
	end
	canary = nil
end

function RolandSecurity:_checkNativeClosures()
	local isCClosure = safeRawGet(self._environment, "iscclosure")
	if type(isCClosure) ~= "function" then
		return
	end
	local names = self._detectorConfig.nativeClosureNames or { "pcall", "xpcall", "type", "tostring" }
	local directBuiltins = { pcall = pcall, xpcall = xpcall, type = type, tostring = tostring }
	local mismatches = 0
	local checked = 0
	for _, name in ipairs(names) do
		local candidate = safeRawGet(self._environment, name) or safeRawGet(_G, name) or directBuiltins[name]
		if type(candidate) == "function" then
			local ok, result = pcall(isCClosure, candidate)
			if ok then
				checked = checked + 1
				if result ~= true then mismatches = mismatches + 1 end
			end
		end
	end
	if checked >= 2 and mismatches >= 2 then
		self:reportSignal("L05_NATIVE_CLOSURE_INVALID", { checkedCount = checked, mismatchCount = mismatches })
	end
end

function RolandSecurity:_checkTiming()
	if self._detectorConfig.enableTiming ~= true then
		return
	end
	local samples = {}
	local iterations = clamp(tonumber(self._detectorConfig.timingIterations) or 256, 64, 2048)
	for sample = 1, 9 do
		local started = self._adapters.clock()
		for _ = 1, iterations do
			pcall(type, sample)
		end
		table.insert(samples, math.max(0, self._adapters.clock() - started))
	end
	local center = median(samples)
	if center <= 0 then return end
	local maximum = math.max(table.unpack(samples))
	local ratio = maximum / center
	local threshold = clamp(tonumber(self._detectorConfig.timingRatio) or 12, 5, 100)
	if ratio >= threshold then
		self:reportSignal("L06_TIMING_ANOMALY", {
			sampleCount = #samples,
			ratioMilli = math.floor(ratio * 1000),
			maxMicros = math.floor(maximum * 1000000),
		}, { confidence = math.min(50, 20 + math.floor(ratio)) })
	end
end

function RolandSecurity:_checkGlobalEnvironment()
	local changesByFamily = { COMPILER = 0, TRANSPORT = 0, ENVIRONMENT = 0 }
	local checked = 0
	for name, captured in pairs(self._captured.globals) do
		checked = checked + 1
		local current = safeRawGet(self._environment, name) or ABSENT_GLOBAL
		if current ~= captured then
			local family = name == "loadstring" and "COMPILER"
				or (name == "request" or name == "http_request" or name == "syn"
					or name == "fluxus" or name == "http") and "TRANSPORT"
				or "ENVIRONMENT"
			changesByFamily[family] = changesByFamily[family] + 1
		end
	end
	for _, family in ipairs({ "COMPILER", "TRANSPORT", "ENVIRONMENT" }) do
		local changes = changesByFamily[family]
		if changes > 0 then
			self:reportSignal("L07_GLOBAL_ENV_MISMATCH", {
				checkedCount = checked,
				changedCount = changes,
				surface = family:lower(),
			}, { riskFamily = family })
		end
	end
end

-- Diagnostic injection exists only to prove the telemetry path in staging.
-- Enabling it requires all three exact gates in new(): deployment, enabled and
-- confirmation. Production/default construction therefore fails closed.
function RolandSecurity:injectDiagnostic(signalCode, vector)
	if not self._diagnosticEnabled then
		return false, "diagnostics-disabled"
	end
	if not SIGNALS[signalCode] then
		return false, "unknown-signal"
	end
	return self:reportSignal(signalCode, {
		variant = "staging-injection",
		vector = safeString(vector or signalCode, signalCode):sub(1, 64),
	})
end

function RolandSecurity:injectAllDiagnosticVectors()
	if not self._diagnosticEnabled then
		return false, "diagnostics-disabled"
	end
	local queued = 0
	for index = 1, 13 do
		local signalCode = string.format("L%02d_", index)
		for knownCode in pairs(SIGNALS) do
			if knownCode:sub(1, 4) == signalCode then
				local ok = self:injectDiagnostic(knownCode, "vector-" .. tostring(index))
				if ok then queued = queued + 1 end
				break
			end
		end
	end
	return queued == 13, queued
end

function RolandSecurity:_checkLoadstringUpvalues()
	local compiler = self._captured.loadstringIdentity
	local isCClosure = safeRawGet(self._environment, "iscclosure")
	local debugLibrary = safeRawGet(self._environment, "debug") or safeRawGet(_G, "debug")
	if type(compiler) ~= "function" or type(isCClosure) ~= "function" or type(debugLibrary) ~= "table" then
		return
	end
	local nativeOk, isNative = pcall(isCClosure, compiler)
	if not nativeOk or isNative ~= true then
		return
	end
	local getUpvalues = safeRawGet(debugLibrary, "getupvalues")
	if type(getUpvalues) ~= "function" then
		return
	end
	local ok, values = pcall(getUpvalues, compiler)
	if ok and type(values) == "table" then
		local count = 0
		for _ in pairs(values) do count = count + 1 end
		if count > 0 then
			self:reportSignal("L08_LOADSTRING_UPVALUE_FOUND", { upvalueCount = math.min(count, 32) })
		end
	end
end

function RolandSecurity:_checkLoadstringSource()
	local allowed = self._detectorConfig.expectedLoadstringSources
	if type(allowed) ~= "table" or #allowed == 0 then
		return
	end
	local compiler = self._captured.loadstringIdentity
	local debugLibrary = safeRawGet(self._environment, "debug") or safeRawGet(_G, "debug")
	local info = type(debugLibrary) == "table" and safeRawGet(debugLibrary, "info") or nil
	if type(compiler) ~= "function" or type(info) ~= "function" then
		return
	end
	local ok, source = pcall(info, compiler, "s")
	if not ok or type(source) ~= "string" then
		return
	end
	for _, expected in ipairs(allowed) do
		if source == expected then return end
	end
	self:reportSignal("L09_LOADSTRING_SOURCE_INVALID", { sourceDigest = sha256(source), sourceLength = #source })
end

function RolandSecurity:_checkUiArtifacts()
	local names = self._detectorConfig.uiArtifactNames
	local sampler = self._detectorConfig.uiArtifactSampler
	if (type(names) ~= "table" or #names == 0) and type(sampler) ~= "function" then
		return
	end
	local matched = {}
	if type(sampler) == "function" then
		local ok, result = pcall(sampler, 64)
		if ok and type(result) == "table" then
			local seen = {}
			for _, rawName in pairs(result) do
				if #matched >= 64 then break end
				if type(rawName) == "string" then
					local normalized = rawName:gsub("%c", ""):lower():sub(1, 128)
					if normalized ~= "" and not seen[normalized] then
						seen[normalized] = true
						table.insert(matched, normalized)
					end
				end
			end
		end
	else
		local wanted = {}
		for index = 1, math.min(#names, 128) do
			if type(names[index]) == "string" then
				wanted[names[index]:lower():sub(1, 128)] = true
			end
		end
		local gameObject = safeRawGet(self._environment, "game") or safeRawGet(_G, "game")
		if gameObject == nil then
			local ok, direct = pcall(function() return game end)
			if ok then gameObject = direct end
		end
		if gameObject ~= nil then
			pcall(function()
				local coreGui = gameObject:GetService("CoreGui")
				local children = coreGui:GetChildren()
				for index = 1, math.min(#children, 64) do
					local childName = tostring(children[index].Name):lower()
					if wanted[childName] then table.insert(matched, childName) end
				end
			end)
		end
	end
	if #matched > 0 then
		table.sort(matched)
		self:reportSignal("L10_UI_ARTIFACT_FOUND", { matchCount = #matched, matchDigest = sha256(table.concat(matched, "\n")) })
	end
end

function RolandSecurity:_checkHttpChannel()
	local current = resolveRequest(self._environment)
	local positive = self._captured.requestIdentity ~= nil and current ~= self._captured.requestIdentity
	local method = positive and "identity-change" or nil
	local isFunctionHooked = safeRawGet(self._environment, "isfunctionhooked")
	if type(isFunctionHooked) == "function" and type(current) == "function" then
		local ok, hooked = pcall(isFunctionHooked, current)
		if ok and hooked == true then
			positive = true
			method = "executor-introspection"
		end
	end
	if positive then
		self:reportSignal("L11_HTTP_CHANNEL_HOOKED", { variant = method or "unknown" })
	end
end

function RolandSecurity:runChecks(phase)
	if self._state ~= "ACTIVE" and self._state ~= "QUARANTINED" then
		return false, "not-active"
	end
	local checks = {
		function() self:_checkLoadstringHook() end,
		function() self:_checkLoadstringCanary() end,
		function() self:_checkCanaryExposure() end,
		function() self:_checkNativeClosures() end,
		function() self:_checkTiming() end,
		function() self:_checkGlobalEnvironment() end,
		function() self:_checkLoadstringUpvalues() end,
		function() self:_checkLoadstringSource() end,
		function() self:_checkUiArtifacts() end,
		function() self:_checkHttpChannel() end,
	}
	for index, check in ipairs(checks) do
		local ok = pcall(check)
		if not ok then
			self:_notify("onDetectorError", index, phase or "manual")
		end
	end
	return true
end

function RolandSecurity:verifyPayload(source, envelope)
	assert(type(source) == "string", "payload source must be a string")
	assert(type(envelope) == "table", "payload envelope is required")
	local maximumBytes = clamp(math.floor(tonumber(self._payloadPolicy.maximumBytes) or 1048576), 65536, 4194304)
	if #source > maximumBytes then
		return false, "payload-too-large"
	end
	local actualDigest
	local hashAdapter = self._detectorConfig.hashSha256
	if type(hashAdapter) == "function" then
		local ok, result = pcall(hashAdapter, source)
		if not ok or type(result) ~= "string" or result:match("^[a-fA-F0-9]+$") == nil or #result ~= 64 then
			return false, "hash-adapter-failed"
		end
		actualDigest = result:lower()
	else
		actualDigest = sha256(source)
	end
	if type(envelope.sha256) ~= "string" or envelope.sha256:lower() ~= actualDigest then
		self:reportSignal("L04_PAYLOAD_SIGNATURE_INVALID", { variant = "digest-mismatch", payloadBytes = #source })
		return false, "digest-mismatch"
	end
	if self._allowUnsignedPayload and envelope.signature == nil then
		return true, actualDigest
	end

	local expectedAlgorithm = self._payloadPolicy.algorithm or "Ed25519"
	local expectedKeyId = self._payloadPolicy.publisherKeyId
	local expectedProduct = self._payloadPolicy.productCode
	local expectedBuildId = self._authorizedBuildId or self._payloadPolicy.buildId
	if type(expectedKeyId) ~= "string" or expectedKeyId == ""
		or type(expectedProduct) ~= "string" or expectedProduct == ""
		or type(expectedBuildId) ~= "string" or expectedBuildId == "" then
		return false, "payload-policy-unconfigured"
	end
	if type(envelope.signature) ~= "string" or envelope.signature == ""
		or #envelope.signature ~= 86 or envelope.signature:match("^[%w_-]+$") == nil
		or type(envelope.publisherKeyId) ~= "string" or envelope.publisherKeyId ~= expectedKeyId
		or type(envelope.productCode) ~= "string" or envelope.productCode ~= expectedProduct
		or type(envelope.algorithm) ~= "string" or envelope.algorithm ~= expectedAlgorithm
		or type(envelope.buildId) ~= "string" or envelope.buildId ~= expectedBuildId or #envelope.buildId > 128
		or type(envelope.version) ~= "string" or envelope.version ~= self._clientVersion
		or not isSafeStorageKey(envelope.storageKey) then
		self:reportSignal("L04_PAYLOAD_SIGNATURE_INVALID", { variant = "manifest-invalid", payloadBytes = #source })
		return false, "manifest-invalid"
	end
	if self._authorizedBuild ~= nil then
		local manifest = self._authorizedBuild
		if envelope.sha256:lower() ~= manifest.sha256
			or envelope.signature ~= manifest.signature
			or envelope.algorithm ~= manifest.algorithm
			or envelope.publisherKeyId ~= manifest.publisherKeyId
			or envelope.productCode ~= manifest.productCode
			or envelope.buildId ~= manifest.buildId
			or envelope.version ~= manifest.version
			or envelope.storageKey ~= manifest.storageKey then
			self:reportSignal("L04_PAYLOAD_SIGNATURE_INVALID", { variant = "server-manifest-mismatch", payloadBytes = #source })
			return false, "server-manifest-mismatch"
		end
	end

	local verifier = self._detectorConfig.verifyPayloadSignature
	if type(verifier) ~= "function" then
		return false, "signature-verifier-unavailable"
	end
	local signingMessage = canonicalJson({
		algorithm = envelope.algorithm,
		buildId = envelope.buildId,
		productCode = envelope.productCode,
		publisherKeyId = envelope.publisherKeyId,
		sha256 = actualDigest,
		storageKey = envelope.storageKey,
		version = envelope.version,
	})
	local ok, valid = pcall(verifier, signingMessage, envelope.signature, envelope)
	if not ok or valid ~= true then
		self:reportSignal("L04_PAYLOAD_SIGNATURE_INVALID", { variant = "signature-invalid", payloadBytes = #source })
		return false, "signature-invalid"
	end
	return true, actualDigest
end

function RolandSecurity:compileProtected(source, chunkName)
	local compiler = self._captured.loadstring
	if type(compiler) ~= "function" then
		self:reportSignal("L12_PAYLOAD_COMPILATION_FAILED", { variant = "compiler-unavailable", payloadBytes = #source })
		return nil, "compiler-unavailable"
	end
	local ok, compiledOrError = pcall(compiler, source, chunkName or "=roland-payload")
	if not ok or type(compiledOrError) ~= "function" then
		local errorDigest = sha256(safeString(compiledOrError, "unprintable-compiler-error"))
		self:reportSignal("L12_PAYLOAD_COMPILATION_FAILED", {
			variant = ok and "compile-rejected" or "compiler-error",
			payloadBytes = #source,
			errorDigest = errorDigest,
		})
		return nil, "compilation-failed"
	end
	return compiledOrError
end

function RolandSecurity:runProtected(label, callback, ...)
	assert(type(callback) == "function", "protected callback must be a function")
	self:_checkLeaseWatchdog()
	if self._state ~= "ACTIVE" then
		return false, self._state == "QUARANTINED" and "quarantined" or "not-active"
	end
	self._protectedPayloadStarted = true
	local arguments = table.pack(...)
	local results = table.pack(pcall(function()
		return callback(table.unpack(arguments, 1, arguments.n))
	end))
	if results[1] ~= true then
		local message = safeString(results[2], "unprintable-runtime-error")
		self:reportSignal("L13_RUNTIME_EXECUTION_FAILED", {
			variant = safeString(label or "payload", "payload"):sub(1, 64),
			errorDigest = sha256(message),
			errorLength = #message,
		})
		return false, "runtime-failed"
	end
	return true, table.unpack(results, 2, results.n)
end

function RolandSecurity:executePayload(source, envelope, chunkName, ...)
	local verified, verifyError = self:verifyPayload(source, envelope)
	if not verified then
		return false, verifyError
	end
	local compiled, compileError = self:compileProtected(source, chunkName)
	if not compiled then
		return false, compileError
	end
	return self:runProtected(chunkName or "payload", compiled, ...)
end

function RolandSecurity:getAuthorizedBuild()
	return self._authorizedBuild and shallowCopy(self._authorizedBuild) or nil
end

function RolandSecurity:executeAuthorizedPayload(source, chunkName, ...)
	if self._authorizedBuild == nil then
		return false, "authorized-build-unavailable"
	end
	return self:executePayload(source, self._authorizedBuild, chunkName, ...)
end

function RolandSecurity:downloadAuthorizedPayload()
	self:_checkLeaseWatchdog()
	if self._state ~= "ACTIVE" then
		return false, self._state == "QUARANTINED" and "quarantined" or "not-active"
	end
	if self._authorizedBuild == nil then
		return false, "authorized-build-unavailable"
	end

	local status, source, data, transportError, responseHeaders = self:_getPayload("/v1/runtime/payload")
	if status == 401 or status == 403 or TERMINAL_ERROR_CODES[responseErrorCode(data)] then
		local code = responseErrorCode(data) or "SESSION_DENIED"
		self:_handleTerminal(code, status)
		return false, code
	end
	if status ~= 200 or type(source) ~= "string" then
		return false, responseErrorCode(data) or transportError or ("http-" .. tostring(status))
	end

	local manifest = self._authorizedBuild
	local responseBuildId = headerValue(responseHeaders, "x-roland-build-id")
	local responseVersion = headerValue(responseHeaders, "x-roland-build-version")
	local responseDigest = headerValue(responseHeaders, "x-roland-payload-sha256")
	local contentType = headerValue(responseHeaders, "content-type")
	if responseBuildId ~= manifest.buildId
		or responseVersion ~= manifest.version
		or type(responseDigest) ~= "string"
		or responseDigest:lower() ~= manifest.sha256
		or type(contentType) ~= "string"
		or contentType:lower():match("^text/plain") == nil then
		self:reportSignal("L04_PAYLOAD_SIGNATURE_INVALID", {
			variant = "payload-response-mismatch",
			payloadBytes = #source,
		})
		return false, "payload-response-mismatch"
	end

	local verified, verifyResult = self:verifyPayload(source, manifest)
	if not verified then
		return false, verifyResult
	end
	return true, source, verifyResult
end

function RolandSecurity:downloadAndExecuteAuthorizedPayload(chunkName, ...)
	local downloaded, sourceOrError = self:downloadAuthorizedPayload()
	if not downloaded then
		return false, sourceOrError
	end
	local compiled, compileError = self:compileProtected(sourceOrError, chunkName)
	if not compiled then
		return false, compileError
	end
	return self:runProtected(chunkName or "payload", compiled, ...)
end

function RolandSecurity:start(entrypoint, ...)
	local activated, activationError = self:activate()
	if not activated then
		return false, activationError
	end
	self:_startLoops()
	self:runChecks("startup")
	if self._quarantined then
		return false, "quarantined"
	end
	if entrypoint ~= nil then
		return self:runProtected("entrypoint", entrypoint, ...)
	end
	return true
end

function RolandSecurity:tick()
	if not self._manualScheduling then
		return false, "automatic-scheduling"
	end
	self:_checkLeaseWatchdog()
	if self._adapters.clock() >= self._heartbeatDueAt then
		self:heartbeatOnce()
	end
	self:_checkLeaseWatchdog()
	self:flushEvents()
	return true
end

function RolandSecurity:isExecutionAllowed()
	self:_checkLeaseWatchdog()
	return self._state == "ACTIVE" and not self._quarantined
end

function RolandSecurity:stop(reason)
	if self._state == "STOPPED" then
		return true
	end
	self._stopping = true
	local tokenWasPresent = self._sessionToken ~= nil
	local status = 0
	if tokenWasPresent and (self._state == "ACTIVE" or self._state == "QUARANTINED") then
		status = select(1, self:_post("/v1/runtime/deactivate", {}, true))
	end
	self._sessionToken = nil
	self._state = "STOPPED"
	self:_notify("onStopped", safeString(reason or "client-stop", "client-stop"):sub(1, 128), status)
	return status == 200 or not tokenWasPresent
end

function RolandSecurity:getStatus()
	local leaseRemaining = nil
	if self._leaseDeadlineAt ~= math.huge then
		leaseRemaining = math.max(0, math.floor(self._leaseDeadlineAt - self._adapters.clock()))
	end
	local quarantineCauses = {}
	for reason in pairs(self._quarantineCauses) do
		table.insert(quarantineCauses, reason)
	end
	table.sort(quarantineCauses)
	return {
		state = self._state,
		mode = self._mode,
		quarantined = self._quarantined,
		quarantineReason = self._quarantineReason,
		quarantineCauses = quarantineCauses,
		queuedEvents = #self._eventQueue,
		droppedEvents = self._droppedEvents,
		dedupEntries = self._dedupCount,
		riskObservations = #self._riskObservations,
		lastErrorCode = self._lastErrorCode,
		sessionId = self._sessionId,
		buildId = self._authorizedBuildId,
		nextHeartbeatSequence = self._heartbeatSequence,
		leaseRemainingSeconds = leaseRemaining,
	}
end

RolandSecurity.SIGNALS = SIGNALS
RolandSecurity._internals = {
	sha256 = sha256,
	canonicalJson = canonicalJson,
	sanitizeMetadata = sanitizeMetadata,
	parseHttpResponse = parseHttpResponse,
	parseRawHttpResponse = parseRawHttpResponse,
	headerValue = headerValue,
	isSafeStorageKey = isSafeStorageKey,
	retryAfterSeconds = retryAfterSeconds,
}

return RolandSecurity
end)()

local __RLS_HashSha256 = nil
do
	local cryptLibrary = rawget(__RLS_Environment, "crypt") or rawget(_G, "crypt")
	local hashFunction = type(cryptLibrary) == "table" and rawget(cryptLibrary, "hash") or nil
	if type(hashFunction) == "function" then
		local ok, vector = pcall(hashFunction, "abc", "sha256")
		if ok and type(vector) == "string"
			and vector:lower() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" then
			__RLS_HashSha256 = function(value)
				local hashOk, digest = pcall(hashFunction, value, "sha256")
				if not hashOk or type(digest) ~= "string" then return nil end
				return digest:lower()
			end
		end
	end
end


local __RLS_StopBusy = false
local function __RLS_StopSeaHub(reason)
	if __RLS_StopBusy then return end
	__RLS_StopBusy = true
	rawset(__RLS_Environment, "__ROLAND_SECURITY_STOP_REASON", tostring(reason or "security-stop"))
	local controller = rawget(__RLS_Environment, "SeaHubCleanController")
	if type(controller) == "table" and type(controller.stop) == "function" then
		pcall(controller.stop, controller)
	end
	__RLS_StopBusy = false
end

local previousRuntime = rawget(__RLS_Environment, "__ROLAND_SECURITY_RUNTIME")
if type(previousRuntime) == "table" and type(previousRuntime.stop) == "function" then
	pcall(previousRuntime.stop, previousRuntime, "bootstrap-replaced")
end

local runtime = RolandSecurity.new({
	baseUrl = "https://api-staging-edb8.up.railway.app",
	key = __RLS_LicenseKey,
	clientVersion = "kaitun-2026.10.1",
	deployment = "production",
	mode = "quarantine",
	payloadPolicy = {
		algorithm = "Ed25519",
		publisherKeyId = "publisher-main-2026",
		productCode = "KAITUN",
		maximumBytes = 4194304,
	},
	detectors = {
		hashSha256 = __RLS_HashSha256,
		verifyPayloadSignature = __RLS_VerifyPayloadSignature,
	},
	activation = { startupJitterSeconds = 3, maxAttempts = 3, retryBaseSeconds = 0.25 },
	queue = { maxQueuedEvents = 48, maxEventsPerMinute = 60, dedupSeconds = 60, maxDedupEntries = 256, flushBurst = 3, flushIntervalSeconds = 4 },
	leaseWatchdog = { graceSeconds = 3 },
	callbacks = {
		onServerStop = __RLS_StopSeaHub,
		onQuarantine = __RLS_StopSeaHub,
		onLeaseExpired = __RLS_StopSeaHub,
		onStopped = __RLS_StopSeaHub,
	},
})
__RLS_LicenseKey = nil
rawset(__RLS_Environment, "__ROLAND_SECURITY_RUNTIME", runtime)
local activated, activationError = runtime:start()
if not activated then error("Roland Security activation failed: " .. tostring(activationError), 0) end
local executed, result = runtime:downloadAndExecuteAuthorizedPayload("=SeaHub")
if not executed then
	runtime:stop("payload-start-failed")
	error("Roland Security payload failed: " .. tostring(result), 0)
end
return result
