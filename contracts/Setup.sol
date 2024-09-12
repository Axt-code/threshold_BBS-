// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.7.0 <0.9.0;
pragma experimental ABIEncoderV2;

import {G} from "../libraries/G.sol";

contract Setup {
    // Event to broadcast partial credential issuance
    event PublicParam(address indexed client, uint256[2][] H, string X);

    // Function for partial credential issuance
    function sendPublicParam(G.G1Point[] memory _H, string memory X) public {
        uint256[2][] memory H = new uint256[2][](_H.length);

        for (uint256 i = 0; i < _H.length; i++) {
            H[i] = [_H[i].X, _H[i].Y];
        }

        // uint256[2][2] memory Pk = [_X.X, _X.Y];
        emit PublicParam(msg.sender, H, X);
    }
}
