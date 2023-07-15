rule WormWin32SillyP2PSampleH
{
	meta:
		Description  = "Worm.Silly.sm"
		ThreatLevel  = "5"

	strings:
		$ = "95BC789A" ascii wide
		$ = "svchosts.exe" ascii wide
		$ = "Failed to start dl thread." ascii wide
		$ = "wo8T#$>X&D" ascii wide

		$hex0 = { 55 8b ec 81 ec 8c 06 00 00 56 57 83 ?? ?? ?? ?? ?? ?? 8b ?? ?? b9 a5 00 00 00 8d ?? ?? ?? ?? ?? f3 ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 68 68 42 40 00 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 6a 00 68 60 42 40 00 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 68 58 42 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 83 ?? ?? ?? ?? ?? ?? 74 ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? eb ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 68 38 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 14 8d ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 6a 06 ff ?? ?? e8 ?? ?? ?? ?? 83 c4 10 68 00 02 00 00 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? 83 ?? ?? ?? ?? ?? ?? 74 ?? eb ?? 68 64 41 40 00 68 28 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 eb ?? 8d ?? ?? ?? ?? ?? 50 68 0c 42 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 eb ?? 68 f0 41 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c eb ?? 68 c4 41 40 00 68 ff 01 00 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 8d ?? ?? ?? ?? ?? 50 8d ?? ?? ?? ?? ?? 50 6a 06 ff ?? ?? e8 ?? ?? ?? ?? 83 c4 10 68 00 02 00 00 6a 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 0c 83 ?? ?? ?? ?? ?? ?? 75 ?? ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? e8 ?? ?? ?? ?? 59 6a 00 ff ?? ?? ?? ?? ??}
		$hex1 = { 55 8b ec 81 ec 14 03 00 00 57 80 ?? ?? ?? ?? ?? ?? 6a 40 59 33 c0 8d ?? ?? ?? ?? ?? f3 ?? 66 ?? aa 80 ?? ?? ?? ?? ?? ?? 6a 40 59 33 c0 8d ?? ?? ?? ?? ?? f3 ?? 66 ?? aa 6a 03 8d ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 80 ?? ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 83 f8 02 75 ?? 6a 05 6a 00 8d ?? ?? ?? ?? ?? 50 68 48 41 40 00 68 40 41 40 00 6a 00 ff ?? ?? ?? ?? ?? 68 54 40 40 00 e8 ?? ?? ?? ?? 59 50 68 54 40 40 00 e8 ?? ?? ?? ?? 59 59 68 90 01 00 00 ff ?? ?? ?? ?? ?? 68 6c 40 40 00 6a 00 6a 00 ff ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 3d b7 00 00 00 75 ?? 6a 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 89 ?? ?? 68 34 41 40 00 ff ?? ?? e8 ?? ?? ?? ?? 59 59 85 c0 74 ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? a0 ?? ?? ?? ?? 88 ?? ?? 8d ?? ?? 50 e8 ?? ?? ?? ??}
		$hex2 = { 55 8b ec 81 ec 10 03 00 00 83 ?? ?? ?? ?? ?? ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 6a 00 ff ?? ?? ?? ?? ?? 50 ff ?? ?? ?? ?? ?? 68 04 01 00 00 8d ?? ?? ?? ?? ?? 50 68 78 40 40 00 ff ?? ?? ?? ?? ?? 68 84 40 40 00 8d ?? ?? ?? ?? ?? 50 68 74 42 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 68 84 40 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 85 c0 0f ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 c0 42 40 00 68 01 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 c0 42 40 00 68 02 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 8d ?? ?? ?? ?? ?? 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 7c 42 40 00 68 02 00 00 80 ff ?? ?? ?? ?? ?? 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 50 8d ?? ?? ?? ?? ?? 50 6a 01 6a 00 68 94 40 40 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 68 34 41 40 00 8d ?? ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 59 59 0f b6 c0 85 c0 74 ?? 68 c8 00 00 00 ff ?? ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? c9 c3}

	condition:
		(3 of them) or (any of ($hex*))
}