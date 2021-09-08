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
event dce_rpc_response_stub(c: connection, fid: count, ctx_id: count, opnum: count, stub: string) &priority=2
    {
        # Grab the file id for the current outstanding DCE-RPC operations.   We'll need this later to extract
        # the endpoint and operation names from this DCE-RPC response.
        if ( c?$smb_state && c$smb_state?$current_cmd && c$smb_state$current_cmd?$referenced_file && c$smb_state$current_cmd$referenced_file?$fid )
            {
                fid = c$smb_state$current_cmd$referenced_file$fid;
            }
        else
            {
                return;
            }

        # Grab the DCE-RPC endpoint and operation names.
        if ( c?$dce_rpc_backing && fid in c$dce_rpc_backing )
            {
                local dce_rpc = c$dce_rpc_backing[fid];

                if ( dce_rpc?$info && dce_rpc$info?$endpoint )
                    {
                        local ep = dce_rpc$info$endpoint;
                        local operation = dce_rpc$info$operation;
                    }
                else
                    {
                        return;
                    }
            }
        else
            {
                return;
            }


        # The Petit Potam exploit uses the EFSRPC endpoints to trigger an NTLM auth that can be relayed
        if ( ep == "efsrpc" || ep == "efsrpc2" )
            {
                local exploit_status = "";

                # An error code of 0x00000035 (ERROR_BAD_NETPATH) indicates that the exploit worked
                #   https://github.com/topotam/PetitPotam/blob/main/PetitPotam.py#L381
                if ( ends_with(stub, "5\x00\x00\x00") )
                    {
                        exploit_status = "Successful";
                    }
                else
                    {
                        exploit_status = "Failed";
                    }

                # Throw a notice of the exploit attempt and whether it was successful or not
                local msg = fmt("%s PetitPotam NTLM relay attack: %s %s()", exploit_status, ep, operation);
                NOTICE([$note=PetitPotam, $msg=msg, $uid=c$uid, $id=c$id, $identifier=cat(c$id$orig_h, c$id$resp_h, ep, operation)]);
            }
    }

# fin
