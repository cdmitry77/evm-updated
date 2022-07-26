// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"

#include <cassert>
#include <fmt/format_header_only.h>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <vector>

///////////////////////////////////////////////////////////////////////////////
//
// Util typedefs and functions
//
using Addresses = std::vector<eevm::Address>;

struct Environment
{
  eevm::SimpleGlobalState& gs;
  const eevm::Address& owner_address;
  const nlohmann::json& contract_definition;
};

size_t rand_range(size_t exclusive_upper_bound)
{
  std::random_device rand_device;
  std::mt19937 generator(rand_device());
  std::uniform_int_distribution<size_t> dist(0, exclusive_upper_bound - 1);

  return dist(generator);
}

uint256_t get_random_uint256(size_t bytes = 32)
{
  std::vector<uint8_t> raw(bytes);
  std::generate(raw.begin(), raw.end(), []() { return rand(); });
  return eevm::from_big_endian(raw.data(), raw.size());
}

eevm::Address get_random_address()
{
  return get_random_uint256(20);
}
///////////////////////////////////////////////////////////////////////////////

// Run input as an EVM transaction, check the result and return the output
std::vector<uint8_t> run_and_check_result(
  Environment& env,
  const eevm::Address& from,
  const eevm::Address& to,
  const eevm::Code& input)
{
  // Ignore any logs produced by this transaction
  eevm::NullLogHandler ignore;
  eevm::Transaction tx(from, ignore);

  // Record a trace to aid debugging
  eevm::Trace tr;
  eevm::Processor p(env.gs);

  // Run the transaction
  const auto exec_result = p.run(tx, from, env.gs.get(to), input, 0u, &tr);

  if (exec_result.er != eevm::ExitReason::returned)
  {
    // Print the trace if nothing was returned
    std::cerr << fmt::format("Trace:\n{}", tr) << std::endl;
    if (exec_result.er == eevm::ExitReason::threw)
    {
      // Rethrow to highlight any exceptions raised in execution
      throw std::runtime_error(
        fmt::format("Execution threw an error: {}", exec_result.exmsg));
    }

    throw std::runtime_error("Deployment did not return");
  }

  return exec_result.output;
}

// Modify code to append ABI-encoding of arg, suitable for passing to contract
// execution
void append_argument(std::vector<uint8_t>& code, const std::vector<uint8_t>& arg)
{
  // To ABI encode a function call with a uint256_t (or Address) argument,
  // simply append the big-endian byte representation to the code (function
  // selector, or bin). ABI-encoding for more complicated types is more
  // complicated, so not shown in this sample.
  const auto pre_size = code.size();
  code.resize(pre_size + 32u);
  std::memcpy(code.data() + pre_size, arg.data(), arg.size());
}

void append_argument256(std::vector<uint8_t>& code, const uint256_t& arg)
{
  // To ABI encode a function call with a uint256_t (or Address) argument,
  // simply append the big-endian byte representation to the code (function
  // selector, or bin). ABI-encoding for more complicated types is more
  // complicated, so not shown in this sample.
  const auto pre_size = code.size();
  code.resize(pre_size + 32u);
  eevm::to_big_endian(arg, code.data() + pre_size);
}

// Deploy the ERC20 contract defined in env, with total_supply tokens. Return
// the address the contract was deployed to
eevm::Address deploy_contract(
  Environment& env)
{
  // Generate the contract address
  const auto contract_address = eevm::generate_address(env.owner_address, 0u);

  // Get the binary constructor of the contract
  auto contract_constructor = eevm::to_bytes(env.contract_definition["bin"]);
  std::cout << "Contract constructor created: "
            << eevm::to_hex_string(contract_constructor) << std::endl;
  // The constructor takes a single argument (total_supply) - append it
  //append_argument(contract_constructor, total_supply);

  // Set this constructor as the contract's code body
  auto contract = env.gs.create(contract_address, 0u, contract_constructor);

  // Run a transaction to initialise this account
  auto result =
    run_and_check_result(env, env.owner_address, contract_address, {});
  std::cout << "Deploy result: " << eevm::to_hex_string(result) << std::endl;

  // Result of running the compiled constructor is the code that should be the
  // contract's body (constructor will also have setup contract's Storage)
  contract.acc.set_code(std::move(result));

  return contract.acc.get_address();
}

// Get the total token supply by calling totalSupply on the contract_address
uint256_t get_total_supply(
  Environment& env, const eevm::Address& contract_address)
{
  // Anyone can call totalSupply - prove this by asking from a randomly
  // generated address
  const auto caller = get_random_address();

  const auto function_call =
    eevm::to_bytes(env.contract_definition["hashes"]["totalSupply()"]);

  const auto output =
    run_and_check_result(env, caller, contract_address, function_call);

  return eevm::from_big_endian(output.data(), output.size());
}

// Get the current token balance of target_address by calling balanceOf on
// contract_address
//uint256_t get_balance(
//  Environment& env,
//  const eevm::Address& contract_address,
//  const eevm::Address& target_address)
//{
//  // Anyone can call balanceOf - prove this by asking from a randomly generated
//  // address
//  const auto caller = get_random_address();
//
//  auto function_call =
//    eevm::to_bytes(env.contract_definition["hashes"]["balanceOf(address)"]);
//
//  append_argument(function_call, target_address);
//
//  const auto output =
//    run_and_check_result(env, caller, contract_address, function_call);
//
//  return eevm::from_big_endian(output.data(), output.size());
//}

//// Transfer tokens from source_address to target_address by calling transfer on
//// contract_address
//bool transfer(
//  Environment& env,
//  const eevm::Address& contract_address,
//  const eevm::Address& source_address,
//  const eevm::Address& target_address,
//  const uint256_t& amount)
//{
//  // To transfer tokens, the caller must be the intended source address
//  auto function_call = eevm::to_bytes(
//    env.contract_definition["hashes"]["transfer(address,uint256)"]);
//
//  append_argument(function_call, target_address);
//  append_argument(function_call, amount);
//
//  std::cout << fmt::format(
//                 "Transferring {} from {} to {}",
//                 eevm::to_lower_hex_string(amount),
//                 eevm::to_checksum_address(source_address),
//                 eevm::to_checksum_address(target_address))
//            << std::endl;
//
//  const auto output =
//    run_and_check_result(env, source_address, contract_address, function_call);
//
//  // Output should be a bool in a 32-byte vector.
//  if (output.size() != 32 || (output[31] != 0 && output[31] != 1))
//  {
//    throw std::runtime_error("Unexpected output from call to transfer");
//  }
//
//  const bool success = output[31] == 1;
//  std::cout << (success ? " (succeeded)" : " (failed)") << std::endl;
//
//  return success;
//}

// Send N randomly generated token transfers. Some will be to new user addresses
template <size_t N>
void run_random_transactions(
  Environment& env, const eevm::Address& contract_address, Addresses& users)
{
  const auto total_supply = get_total_supply(env, contract_address);
  const auto transfer_max = (2 * total_supply) / N;

  for (size_t i = 0; i < N; ++i)
  {
    const auto from_index = rand_range(users.size());
    auto to_index = rand_range(users.size());

    // Occasionally create new users and transfer to them. Also avoids
    // self-transfer
    if (from_index == to_index)
    {
      to_index = users.size();
      users.push_back(get_random_address());
    }

    const auto amount = get_random_uint256() % transfer_max;

    transfer(env, contract_address, users[from_index], users[to_index], amount);
  }
}

eevm::Code toByteCode(eevm::SimpleStorage& st) {
  eevm::Code res;
  
  for (int i = 0; i < 20; ++i) {
    auto key = eevm::to_uint256(std::to_string(i));
    auto val = st.load(key);
    if (val != 0) { 
        
    }
  }
  return res;
}


eevm::Code serializeState(const eevm::SimpleGlobalState::StateEntry& state)
{
  eevm::Code res;
  auto code = state.first.get_code();
  size_t len = code.size();
  auto storageCode = state.second.toByteCode();
  res.resize(64 + 8 + len + 8 + storageCode.size());
  eevm::to_big_endian(state.first.get_address(), res.data()); // address save
  eevm::to_big_endian(state.first.get_balance(), res.data() + 32); // balance save
  std::memcpy(res.data() + 64, &len, 8); // code len save
  std::memcpy(res.data() + 64 + 8, code.data(), len); // code save
  size_t nonce = state.first.get_nonce();
  std::memcpy(res.data() + 64 + 8 + len, &nonce, 8); // nonce save
  std::memcpy(res.data() + 64 + 8 + len + 8, storageCode.data(), storageCode.size()); // simplestorage save
  return res;
}


void executeMethod(
  Environment& env,
  const eevm::Address& contract_address,
  std::string methodName,
  std::string methodSignature)
{
  std::cout << "Method " << methodName << " with address " << methodSignature << " will be executed. " << std::endl;
  bool notCorrect = true;
  int cSign;
  while (notCorrect)
  {
      std::cout << "Input 0 to call from deployer or 1 for another caller: ";
      std::cin >> cSign;
      if (cSign == 0 or cSign ==1)
      {
        notCorrect = false;
      }
  }

  auto function_call = eevm::to_bytes(methodSignature);
  auto posLeft = methodName.find('(');
  auto posRight = methodName.find(')');
  if (posRight - posLeft > 1)
  {
    std::vector<std::string> methodArgs;
    auto args = methodName.substr(posLeft + 1, posRight - posLeft - 1);
    bool endArgs = false;
    while (!endArgs)
    {
      auto posComma = args.find(',');
      if (posComma == -1)
      {
        methodArgs.push_back(args);
        break;
      }
      else
      {
        auto met = args.substr(0, posComma);
        args = args.substr(posComma + 1, args.size());
        methodArgs.push_back(met);
      }
    }
    std::cout << "Next parameters should be entered: " << std::endl;
    
    for (auto a : methodArgs)
    {
      std::cout << a << ": ";
      std::string b;
      std::cin >> b;
      //std::vector<uint8_t> arg = eevm::to_bytes(b);
      uint256_t argAddr = eevm::to_uint256(b);
      append_argument256(function_call, argAddr);
    }
  }
    const auto caller = cSign == 1 ? get_random_address() : env.owner_address;
    std::cout << "Contract will be called from: " << eevm::address_to_hex_string(caller) << std::endl;
    const auto output = run_and_check_result(env, caller, contract_address, function_call);
    std::cout << "Execute result: " << eevm::to_hex_string(output) << std::endl;
    const auto sMgs = serializeState(env.gs.getEntry(contract_address));
    std::cout << "Current state: " << eevm::to_hex_string(sMgs) << std::endl;
    //return eevm::from_big_endian(output.data(), output.size());
  
}


int printContractMenu(nlohmann::json& contractHashes) {
    int cnt = 1;
    std::cout << "0. Print(repeat) menu" << std::endl;
    for (auto a : contractHashes.items())
    {
        std::cout << cnt << ". " << a.key() << std::endl;
        ++cnt;
    }

    std::cout << cnt << ". Get contract deployer" << std::endl;
    ++cnt;
    std::cout << cnt << ". Choose another contract" << std::endl;
    ++cnt;
    std::cout << cnt << ". Finish" << std::endl;
    return cnt;
}

int printMainMenu(const eevm::SimpleGlobalState& gs) {
    auto addresses = gs.getContractAddresses();
    if (addresses.size() > 0) {
        int cnt = 1;
        std::cout << "CONTRACT MENU" << std::endl;
        for (auto a : addresses) {
          std::cout << cnt << ". " << eevm::address_to_hex_string(a) << std::endl;
          ++cnt;
        }
        std::cout << cnt << ". Deploy new contract"<< std::endl;
        ++cnt;
        std::cout << cnt << ". Exit" << std::endl;
        return cnt;
    }
    else {
        std::cout << "There is no contracts in system. Deploy? - 1-Yes / 2-Exit" << std::endl;
        return 2;
    }

}


int mainMenuWorker(eevm::SimpleGlobalState& gs, std::map<eevm::Address, std::pair<eevm::Address, nlohmann::basic_json<>::value_type>>& contracts) {
  int cnt = printMainMenu(gs);
  int choice;
  int incorrectChoiceCounter = 0;
  while (true) {
      std::cout << "Your choice: ";
      std::cin >> choice;
      std::cout << std::endl;
      if (choice < cnt || choice > 1) {
          break;
      }
      else {
        std::cout << "Not correct choice!" << std::endl;
        ++incorrectChoiceCounter;
        if (incorrectChoiceCounter >= 3)             {
            cnt = printMainMenu(gs);
        }
      }
  }
  if (choice == cnt)       {
    return 0;
  }
  if (choice == cnt - 1) {
    //deploy
    // Create an account at a random address, representing the 'owner' who
    // created
    // the ERC20 contract (gets entire token supply initially)
    const auto owner_address = get_random_address();
    // Open the contract definition file
    std::string contract_path;
    nlohmann::json erc20_definition;
    while (true) {
        std::cout << "Input correct contract definition path: ";
        std::cin >> contract_path;
        std::cout << std::endl;
        std::ifstream contract_fstream(contract_path);
        if (!contract_fstream) {
          std::cout << fmt::format(
            "Unable to open contract definition file {}", contract_path);
          continue;
        }
        const auto contracts_definition = nlohmann::json::parse(contract_fstream);
        const auto all_contracts = contracts_definition["contract"];
        erc20_definition = all_contracts["simple"];
        break;
    }



    // Parse the contract definition from file

    std::cout << "Contract will be deployed from: "
              << eevm::address_to_hex_string(owner_address) << std::endl;
    // Create environment
    Environment env{gs, owner_address, erc20_definition};

    auto contractHashes = env.contract_definition["hashes"];

    // Deploy the ERC20 contract
    const auto contract_address = deploy_contract(env);
    contracts.emplace(contract_address, std::make_pair(owner_address, erc20_definition));
    return 1;
  }
  //execute
  eevm::Address contract_address = gs.getContractAddresses()[choice-1];
  Environment env{gs, contracts[contract_address].first, contracts[contract_address].second};
  auto contractHashes = env.contract_definition["hashes"];

  std::cout << "Choosen contract has following methods:" << std::endl;
  std::vector<std::string> contractMethods;
  std::vector<std::string> contractSignatures;

  for (auto a : contractHashes.items())
  {
    contractMethods.push_back(a.key());
    contractSignatures.push_back(a.value());
  }
  int contractMenuCounter = printContractMenu(contractHashes);
  while (true)
  {
    int value = 0;
    std::cout << "Input your choice: ";
    std::cin >> value;
    if (value == contractMenuCounter - 1)
    {
      break;
    }
    if (value == contractMenuCounter)
    {
      return 0;
    }
    if (value == 0)
    {
      printContractMenu(contractHashes);
    }
    if (value > contractMenuCounter || value < 1)
    {
      continue;
    }
    try
    {
      executeMethod(
        env,
        contract_address,
        contractMethods[value - 1],
        contractSignatures[value - 1]);
    }
    catch (const std::runtime_error& e)
    {
      std::cout << e.what();
    }
    catch (const std::invalid_argument& e)
    {
      std::cout << e.what();
    }
  }

}

// - Contract main - runs different contracts depending of the input json-file
int main(int argc, char** argv)
{
    //create global storage
    eevm::SimpleGlobalState gs;
    std::map<eevm::Address, std::pair<eevm::Address, nlohmann::basic_json<>::value_type>> contracts;
    srand(time(nullptr));
    int menuItem = 0;
    while (mainMenuWorker(gs, contracts) != 0) {}

    // Create an account at a random address, representing the 'owner' who created
    // the ERC20 contract (gets entire token supply initially)
    //const auto owner_address = get_random_address();

    //// Open the contract definition file
    //const auto contract_path = argv[1];
    //std::ifstream contract_fstream(contract_path);
    //if (!contract_fstream)
    //{
    //    std::cout << fmt::format("Unable to open contract definition file {}", contract_path);
    //}

    //// Parse the contract definition from file
    //const auto contracts_definition = nlohmann::json::parse(contract_fstream);
    //const auto all_contracts = contracts_definition["contract"];
    //const auto erc20_definition = all_contracts["simple"];

    //std::cout << "Contract will be deployed from: "
    //        << eevm::address_to_hex_string(owner_address) << std::endl;
    //// Create environment
    //Environment env{gs, owner_address, erc20_definition};

    //auto contractHashes = env.contract_definition["hashes"];

    //// Deploy the ERC20 contract
    //const auto contract_address = deploy_contract(env);

    //std::cout << "Deployed contract has following methods:" << std::endl;
    //std::vector<std::string> contractMethods;
    //std::vector<std::string> contractSignatures;

    //for (auto a : contractHashes.items())
    //{
    //contractMethods.push_back(a.key());
    //contractSignatures.push_back(a.value());
    //}
    //int cnt = printContractMenu(contractHashes);



    return 0;
}
