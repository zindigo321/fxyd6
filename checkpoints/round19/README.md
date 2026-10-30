# R19 conditional offline research checkpoint

R19 completed the full 60,004-member single-replacement neighborhood around
the fixed R18 N28 incumbent. No further qualified improvement was found;
the R18 result and its orbit CSV remain selected.

| Processing | Independently verified |
| --- | ---: |
| Internal-gap certificate: cannot improve the incumbent | 52,948 |
| T100 certificate: original feasibility limit fails | 7,053 |
| T90 certificate | 0 |
| Full evaluation | 3 |
| Total | 60,004 |

Unprocessed, unknown and candidate-result reuse are all zero. A gap certificate
does not establish infeasibility and is not a full evaluation. The conclusion
applies only to this one fixed-center single-swap neighborhood.

The original B0 remains the reference for mask T90/T100 and pooled internal
Tavg constraints. The R18 incumbent is the reference for the conservative
one-second Tmax improvement requirement. Candidate gap means use their
actual internal-gap counts.

| Retained metric | Seconds |
| --- | ---: |
| mask T90 | 283626.3948020579 |
| mask T100 | 595089.2108747589 |
| pooled internal Tavg, 175 gaps | 9251.526570870468 |
| internal Tmax | 132051.28738869302 |
| boundary-inclusive Tmax | 136700.71607742802 |

Mask coverage is 43070/43070; original-domain coverage is 43070/43424 and
original-domain T100 remains null. Boundary costs are unchanged from R18.

Selected identity:
`fa31ae444cd7afcf008b9d8d4d10a8ce6a8b8533c4d8f68c27bcf0003106d372`.
The selected orbit file is [the existing R18 CSV](../round18/selected_orbits.csv),
5199 bytes, SHA-256
`7b9480f8a1aef119b73cd2e1732ce45845b1634886492a8c5857636ad8654365`.
R19 does not duplicate or rewrite that artifact.

The first formal attempt failed because terminal verification compared
floating numeric rank fields exactly. The main/checker mean difference was
1.8189894035458565e-12 seconds against a declared 1e-6-second tolerance.
The checker and related tests were corrected, then all four jobs and all
60,004 candidates were rerun under the final frozen source. The original
FAIL and logs remain preserved; they are not relabelled PASS.

The final source snapshot contains 292 files, with 268 prior consumed files
and four R18 checkpoint inputs preserved byte-for-byte. There are 76 new
tests, 464 historical tests and 26 historical binding counterexamples.
R19's new guards deny socket.* audit events in every execution role, covering
the prior export sendto/getaddrinfo gap. This is Python audit protection,
not operating-system isolation.

All final research/export/launcher/Shell/finalizer exit records are zero.
Receipt creation occurred at 2171.585499965673 seconds; the later outer
readback completed at 2310.8411545391136 seconds, including preparation.
The two timing boundaries are distinct.

This remains conditional TEAM_COMPETITION_V3 archived-component research.
Saved mixed altitudes, the 0.81-degree half-angle/direct-AreaTarget protocol
and the temporary mask are not confirmed official rules. EOP ends in 2019
while the scenario is in 2027. Official readiness is UNRESOLVED, official
score is null, and there is no new whole-constellation STK validation.
Saved components do not establish continuous geometric completeness.

The original delivery is retained locally at
`G:\gpt-file\Codex\outputs\bd-fmb\round19\20261030T075253_offline`;
the later observation is under the corresponding `G:\fmb666\work\round19`
directory. The compact [evidence record](evidence.json) binds their hashes.
Some preflight/failed histories remain only in original work and are indexed
in the delivery; the index is not their full log. Large inputs, full work and
delivery archives are not part of this Git checkpoint. A fresh clone alone
does not contain all local inputs needed for the scientific replay.
