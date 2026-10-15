-- Scoped experimental port of nfqws1 hostfakesplit altorder=1.
-- Derived from bol-van/zapret2 v1.0.5.2 lua/zapret-antidpi.lua hostfakesplit.
-- Keep the upstream helpers, reassembly/replay handling and fooling semantics.
-- Only packet order differs: prefix, fake host, suffix, genuine host pieces.
-- Apply exclusively to tls_client_hello in bounded outgoing packet ranges.
function hostfakesplit_alt1(ctx, desync)
    if not desync.dis.tcp then
        if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
        return
    end
    direction_cutoff_opposite(ctx, desync)
    if desync.arg.optional and desync.arg.blob and not blob_exist(desync, desync.arg.blob) then
        return
    end
    local data = blob_or_def(desync, desync.arg.blob) or desync.reasm_data or desync.dis.payload
    if #data > 0 and direction_check(desync) and payload_check(desync) then
        if replay_first(desync) then
            local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
            if pos then
                local opts_orig = {
                    rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {},
                    ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}
                }
                local opts_fake = {
                    rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync),
                    ipfrag = {}, ipid = desync.arg, fooling = desync.arg
                }
                local part = string.sub(data, 1, pos[1]-1)
                if not rawsend_payload_segmented(desync, part, 0, opts_orig) then
                    return VERDICT_PASS
                end
                local fakehost = genhost(pos[2]-pos[1]+1, desync.arg.host)
                if not rawsend_payload_segmented(desync, fakehost, pos[1]-1, opts_fake) then
                    return VERDICT_PASS
                end
                -- altorder=1: suffix comes BEFORE the genuine hostname.
                part = string.sub(data, pos[2]+1)
                if not rawsend_payload_segmented(desync, part, pos[2], opts_orig) then
                    return VERDICT_PASS
                end
                local midhost
                if desync.arg.midhost then
                    midhost = resolve_pos(data, desync.l7payload, desync.arg.midhost)
                    if midhost and (midhost <= pos[1] or midhost > pos[2]) then
                        midhost = nil
                    end
                end
                if midhost then
                    part = string.sub(data, pos[1], midhost-1)
                    if not rawsend_payload_segmented(desync, part, pos[1]-1, opts_orig) then
                        return VERDICT_PASS
                    end
                    part = string.sub(data, midhost, pos[2])
                    if not rawsend_payload_segmented(desync, part, midhost-1, opts_orig) then
                        return VERDICT_PASS
                    end
                else
                    part = string.sub(data, pos[1], pos[2])
                    if not rawsend_payload_segmented(desync, part, pos[1]-1, opts_orig) then
                        return VERDICT_PASS
                    end
                end
                replay_drop_set(desync)
                return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
            end
        end
        if replay_drop(desync) then
            return desync.arg.nodrop and VERDICT_PASS or VERDICT_DROP
        end
    end
    return VERDICT_PASS
end
