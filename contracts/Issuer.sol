// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {G} from "../libraries/G.sol";

contract Issuer {
    // mapping(uint256 => G.G1Point[]) public r_i;

    // Event to broadcast partial credential issuance
    event PartialCredential(
        address indexed client,
        uint256 sid,
        uint256 sigid,
        uint256 e,
        uint256 s,
        uint u_i,
        uint256[2] r
    );

    // Function for partial credential issuance
    function issuePartialCredential(
        uint256 sid,
        uint256 sigid,
        uint256 e,
        uint256 s,
        uint u_i,
        G.G1Point memory r_i
    ) public {
        uint256[2] memory r = [r_i.X, r_i.Y];

        emit PartialCredential(msg.sender, sid, sigid, e, s, u_i, r);
    }
}
