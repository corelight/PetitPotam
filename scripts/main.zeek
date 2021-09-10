#
# Detect attempts to use the Petit Potam exploit to create an NTLM relay attack
#

module PetitPotam;


redef enum Notice::Type += {
	PetitPotam,
};


#
# Detecting Petit Potam exploit attempts is easiest to achieve by examining the responses to DCE-RPC calls.
# The "_stub" variant of the event is used in order to examine the reponse's error code which are encoded in
# the last four bytes of the stub.
#
event dce_rpc_response_stub(c: connection, fid: count, ctx_id: count,
							opnum: count, stub: string) &priority=2
	{
		if ( ! c?$dce_rpc_backing ||  fid !in c$dce_rpc_backing )
			return;

		# locate the saved state regarding the DCERPC request that matches this response
		local dce_rpc = c$dce_rpc_backing[fid];


		if ( ! dce_rpc?$info || ! dce_rpc$info?$endpoint )
			return;

		# Grab the DCE-RPC endpoint and operation names.
		local ep = dce_rpc$info$endpoint;
		local operation = dce_rpc$info$operation;


		# The Petit Potam exploit uses the EFSRPC endpoints to trigger an NTLM auth that can be relayed
		if ( ep == "efsrpc" || ep == "efsrpc2" )
			{
				local exploit_status = "Failed";

				# An error code of 0x00000035 (ERROR_BAD_NETPATH) indicates that the exploit worked
				#   https://github.com/topotam/PetitPotam/blob/main/PetitPotam.py#L381
				if ( ends_with(stub, "\x35\x00\x00\x00") )
					{
						exploit_status = "Successful";
					}

				# print(c);

				# Throw a notice of the exploit attempt and whether it was successful or not
				local msg = fmt("%s PetitPotam NTLM relay attack: %s %s()", exploit_status, ep, operation);
				NOTICE([$note=PetitPotam, $msg=msg, $uid=c$uid, $id=c$id, $identifier=cat(c$id$orig_h, c$id$resp_h, ep, operation)]);
			}
	}

# fin
