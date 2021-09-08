# PetitPotam NTLM Relay Attack Detection

A Zeek package for detecting some attempts to trigger NTLM relay attacks via the Petit Potam exploit.
This package will detect what appear to be successful and unsuccessful exploit attempts.  It makes a
distinction between them by examining the return code for the EFS DCERPC function calls.

NOTE:  This package only detects exploit attempts that are transported over unencrypted SMB.  DCERPC
       calls over encrypted SMB will not be detected.  In these cases it is sometimes possible to
       examin the ntlm.log output for signs of a successful NTLM relay attack in progress.

## Installation

The easiest way to install this package is through [zkg](https://docs.zeek.org/projects/package-manager/en/stable/zkg.html):

```zkg install corelight/petitpotam```

## Usage

Use `./testing/Traces/UnPatchedDCOpenFileRaw.pcapng` and you can follow along

```
% zeek -Cr ./testing/Traces/UnPatchedDCOpenFileRaw.pcapng ./scripts/main.zeek

% cat ./notice.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	notice
#open	2021-09-08-09-40-22
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc	proto	note	msg	sub	src	dst	p	n	peer_descr	actions	email_dest	suppress_for	remote_location.country_code	remote_location.region	remote_location.city	remote_location.latitude	remote_location.longitude
#types	time	string	addr	port	addr	port	string	string	string	enum	enum	string	string	addr	addr	port	count	string	set[enum]	set[string]	interval	string	string	string	double	double
1630594391.099325	CyNNkV2Rl7jrlWadG7	192.168.0.15	33524	192.168.0.85	445	-	-	-	tcp	PetitPotam::PetitPotam	Successful PetitPotam NTLM relay attack: efsrpc2 EfsRpcOpenFileRaw()	-	192.168.0.15	192.168.0.85	445	-	-	Notice::ACTION_LOG	(empty)	3600.000000	-	-	-	-	-
#close	2021-09-08-09-40-22

% cat ./dce_rpc.log
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	dce_rpc
#open	2021-09-08-09-40-22
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	rtt	named_pipe	endpoint	operation
#types	time	string	addr	port	addr	port	interval	string	string	string
1630594365.186353	Cdyntb1vGsZnt6aus7	192.168.0.85	57206	192.168.0.80	49677	0.001003	49677	drsuapi	DRSUnbind
1630594365.187814	Cdyntb1vGsZnt6aus7	192.168.0.85	57206	192.168.0.80	49677	0.000819	49677	drsuapi	DRSUnbind
1630594390.076173	CyNNkV2Rl7jrlWadG7	192.168.0.15	33524	192.168.0.85	445	1.023152	\\pipe\\lsass	efsrpc2	EfsRpcOpenFileRaw
1630594416.810307	CDjrA835p6W6vhm4sg	192.168.0.85	57210	192.168.0.80	49677	0.001444	49677	drsuapi	DRSGetNCChanges
#close	2021-09-08-09-40-22
```

## Additional References

- https://github.com/topotam/PetitPotam
- https://www.bleepingcomputer.com/news/microsoft/new-petitpotam-attack-allows-take-over-of-windows-domains/
- https://www.bleepingcomputer.com/news/security/microsoft-shares-mitigations-for-new-petitpotam-ntlm-relay-attack/
- https://msrc.microsoft.com/update-guide/vulnerability/ADV210003
- https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429

## License

Copyright (c) 2021, Corelight, Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

(1) Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.

(2) Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in the
    documentation and/or other materials provided with the distribution.

(3) Neither the name of Broala, Inc., nor the names of contributors may be 
    used to endorse or promote products derived from this software without 
    specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
