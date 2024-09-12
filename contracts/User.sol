// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;

import {G} from "../libraries/G.sol";

contract User {
    event SigReqBroadcast(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        string[] attribute,
        uint256[2] B_dash,
        uint256[] k,
        uint256 c
    );

    function broadcastSigReq(
        uint256 sid,
        uint256 sigid,
        string[] calldata attribute,
        G.G1Point memory _B_dash,
        uint256[] calldata k,
        uint256 c
    ) external {
        uint256[2] memory B_dash = [_B_dash.X, _B_dash.Y];
        emit SigReqBroadcast(msg.sender, sid, sigid, attribute, B_dash, k, c);
    }

    struct SPOKParams {
        uint256 c;
        uint256 re;
        uint256 rr2;
        uint256 rr3;
        uint256 rs_dash;
        uint256 _timestamp;
        uint256[] rm;
    }

    struct G1Points {
        uint256[2] A_dash;
        uint256[2] A_bar;
        uint256[2] d;
    }

    event SPOKBroadcast(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        SPOKParams params,
        G1Points points
    );

    function broadcastSPOK(
        uint256 sid,
        uint256 sigid,
        SPOKParams memory params,
        G.G1Point memory A_dash,
        G.G1Point memory A_bar,
        G.G1Point memory d
    ) public {
        G1Points memory points = G1Points(
            [A_dash.X, A_dash.Y],
            [A_bar.X, A_bar.Y],
            [d.X, d.Y]
        );

        emit SPOKBroadcast(msg.sender, sid, sigid, params, points);
    }
}
