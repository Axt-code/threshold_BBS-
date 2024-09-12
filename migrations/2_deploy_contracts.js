var G2 = artifacts.require("libraries/BN256G2.sol");
var BnCurve = artifacts.require("libraries/G.sol");
var Setup = artifacts.require("contracts/Setup.sol");
var User = artifacts.require("contracts/User.sol");
var Issuer = artifacts.require("contracts/Issuer.sol");

const deploymentAddress = "0x9925A22E6E8Ddae43a8581c277Ce7419f04c0c6f";

module.exports = async function (deployer) {
  try {
    // Deploy and link libraries
    await deployer.deploy(G2, { from: deploymentAddress });
    const g2 = await G2.deployed();

    await deployer.link(G2, BnCurve);
    await deployer.deploy(BnCurve, { from: deploymentAddress });
    const bnCurve = await BnCurve.deployed();

    // Link BnCurve to Setup and Issuer before deploying them


    await deployer.deploy(Setup, { from: deploymentAddress });
    const setupInstance = await Setup.deployed();

    await deployer.deploy(User, { from: deploymentAddress });
    const userInstance = await User.deployed();

    await deployer.deploy(Issuer, { from: deploymentAddress });
    const issuerInstance = await Issuer.deployed();

    await deployer.link(BnCurve, [Setup, Issuer, User]);
    // Log deployed contract addresses
    console.log(setupInstance.address);
    console.log(userInstance.address);
    console.log(issuerInstance.address);

  } catch (error) {
    console.error("Error deploying contracts:", error);
  }
};
