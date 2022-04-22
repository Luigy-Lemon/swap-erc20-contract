// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.12;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";

contract SwapERC20 is Ownable {
    using SafeERC20 for IERC20;

    // bytes4(keccak256(bytes("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
    bytes4 constant _PERMIT_SIGNATURE = 0xd505accf;

    // Swap ratio from TOKEN_X to TOKEN_Y multiplied by 1e10 eg: 10000000000 = 1:1 swap if both have same decimals, 4200000000 = 100:42 swap meaning that for every 100 TOKEN_X you get 42 TOKEN_Y.
    uint256 public SWAP_RATIO = 10000000000;

    // TOKEN_X token address
    IERC20 public immutable tokenX;

    // TOKEN_Y token address
    IERC20 public immutable tokenY;

    // UNIX time in seconds when the owner will be able to withdraw the remaining TOKEN_Y tokens
    uint256 public withdrawTimeout;

    /**
     * @dev Emitted when someone swap TOKEN_X for TOKEN_Y
     */
    event SwapXtoY(
        uint256 tokenXAmount,
        uint256 tokenYAmount,
        address indexed grantee
    );

    /**
     * @dev Emitted when the owner increases the timeout
     */
    event NewWithdrawTimeout(uint256 newWithdrawTimeout);

     /**
     * @dev Emitted when the owner modifies the SWAP_RATIO
     */
    event NewSwapRatio(uint256 newSwapRatio);


    /**
     * @dev Emitted when the owner withdraw tokens
     */
    event WithdrawTokens(address tokenAddress, uint256 amount);

    /**
     * @dev This contract will receive TOKEN_Y tokens, the users will be able to swap their TOKEN_X tokens for TOKEN_Y tokens
     *      as long as this contract holds enough amount. The swapped TOKEN_X tokens will be burned.
     *      Once the withdrawTimeout is reached, the owner will be able to withdraw the remaining TOKEN_Y tokens.
     * @param _tokenX TOKEN_X token address
     * @param _tokenY TOKEN_Y token address
     * @param duration Time in seconds that the owner will not be able to withdraw the TOKEN_Y tokens
     */
    constructor(
        IERC20 _tokenX,
        IERC20 _tokenY,
        uint256 duration,
        uint256 swapRatio
    ) {
        tokenX = _tokenX;
        tokenY = _tokenY;
        withdrawTimeout = block.timestamp + duration;
        SWAP_RATIO = swapRatio;
    }

    /**
     * @notice Method that allows swap TOKEN_X for TOKEN_Y tokens at the ratio of 1 TOKEN_X --> 1.0000000000 TOKEN_Y
     * Users can either use the permit functionality, or approve previously the tokens and send an empty _permitData
     * @param tokenXAmount Amount of TOKEN_X to swap
     * @param _permitData Raw data of the call `permit` of the token
     */
    function swapXtoY(uint256 tokenXAmount, bytes calldata _permitData)
        public
    {
        // receive and burn TOKEN_X tokens
        if (_permitData.length != 0) {
            _permit(address(tokenX), tokenXAmount, _permitData);
        }

        tokenX.safeTransferFrom(msg.sender, address(this), tokenXAmount);
        ERC20Burnable(address(tokenX)).burn(tokenXAmount);

        // transfer TOKEN_Y tokens
        uint256 tokenYAmount = (tokenXAmount * SWAP_RATIO) / 1e10;
        tokenY.safeTransfer(msg.sender, tokenYAmount);

        emit SwapXtoY(tokenXAmount, tokenYAmount, msg.sender);
    }

    /**
     * @notice Method that allows the owner to withdraw any token from this contract
     * In order to withdraw TOKEN_Y tokens the owner must wait until the withdrawTimeout expires
     * @param tokenAddress Token address
     * @param amount Amount of tokens to withdraw
     */
    function withdrawTokens(address tokenAddress, uint256 amount)
        public
        onlyOwner
    {
        if (tokenAddress == address(tokenY)) {
            require(
                block.timestamp > withdrawTimeout,
                "SwapERC20::withdrawTokens: TIMEOUT_NOT_REACHED"
            );
        }

        IERC20(tokenAddress).safeTransfer(owner(), amount);

        emit WithdrawTokens(tokenAddress, amount);
    }

    /**
     * @notice Method that allows the owner to modify the swap ratio
     * @param newSwapRatio new swap ratio
     */
    function modifySwapRatio(uint256 newSwapRatio) public onlyOwner {
        SWAP_RATIO = newSwapRatio;    
        emit NewSwapRatio(newSwapRatio);    
    }


    /**
     * @notice Method that allows the owner to increase the withdraw timeout
     * @param newWithdrawTimeout new withdraw timeout
     */
    function setWithdrawTimeout(uint256 newWithdrawTimeout) public onlyOwner {
        require(
            newWithdrawTimeout > withdrawTimeout,
            "SwapERC20::setWithdrawTimeout: NEW_TIMEOUT_MUST_BE_HIGHER"
        );

        withdrawTimeout = newWithdrawTimeout;

        emit NewWithdrawTimeout(newWithdrawTimeout);
    }

    /**
     * @notice Function to extract the selector of a bytes calldata
     * @param _data The calldata bytes
     */
    function _getSelector(bytes memory _data)
        private
        pure
        returns (bytes4 sig)
    {
        assembly {
            sig := mload(add(_data, 32))
        }
    }

    /**
     * @notice Function to call token permit method of extended ERC20
     + @param token ERC20 token address
     * @param _amount Quantity that is expected to be allowed
     * @param _permitData Raw data of the call `permit` of the token
     */
    function _permit(
        address token,
        uint256 _amount,
        bytes calldata _permitData
    ) internal {
        bytes4 sig = _getSelector(_permitData);
        require(
            sig == _PERMIT_SIGNATURE,
            "SwapERC20::_permit: NOT_VALID_CALL"
        );
        (
            address owner,
            address spender,
            uint256 value,
            uint256 deadline,
            uint8 v,
            bytes32 r,
            bytes32 s
        ) = abi.decode(
                _permitData[4:],
                (address, address, uint256, uint256, uint8, bytes32, bytes32)
            );
        require(
            owner == msg.sender,
            "SwapERC20::_permit: PERMIT_OWNER_MUST_BE_THE_SENDER"
        );
        require(
            spender == address(this),
            "SwapERC20::_permit: SPENDER_MUST_BE_THIS"
        );
        require(
            value == _amount,
            "SwapERC20::_permit: PERMIT_AMOUNT_DOES_NOT_MATCH"
        );

        // we call without checking the result, in case it fails and he doesn't have enough balance
        // the following transferFrom should be fail. This prevents DoS attacks from using a signature
        // before the smartcontract call
        /* solhint-disable avoid-low-level-calls */
        address(token).call(
            abi.encodeWithSelector(
                _PERMIT_SIGNATURE,
                owner,
                spender,
                value,
                deadline,
                v,
                r,
                s
            )
        );
    }
}
