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

void append_arguments(std::vector<uint8_t>& code, const std::vector<uint256_t>& arg)
{
  const auto pre_size = code.size();
  const auto additional_size = arg.size();
  code.resize(pre_size + additional_size);
  size_t cnt = 0;
  for (auto& a : arg) {
    eevm::to_big_endian(a, code.data() + pre_size + cnt * 32);
  }
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
  Environment& env, std::vector<uint256_t> contractParameters, uint256_t contractBalance, uint64_t nonce)
{
  // Generate the contract address
  const auto contract_address = eevm::generate_address(env.owner_address, nonce);

  // Get the binary constructor of the contract
  auto contract_constructor = eevm::to_bytes(env.contract_definition["bin"]);
  append_arguments(contract_constructor, contractParameters);


  // Set this constructor as the contract's code body
  auto contract = env.gs.create(contract_address, contractBalance, contract_constructor);

  // Run a transaction to initialise this account
  auto result =
    run_and_check_result(env, env.owner_address, contract_address, {});
  std::cout << "Deploy result: " << eevm::to_hex_string(result) << std::endl;

  // Result of running the compiled constructor is the code that should be the
  // contract's body (constructor will also have setup contract's Storage)
  contract.acc.set_code(std::move(result));

  return contract.acc.get_address();
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
    //const auto sMgs = serializeState(env.gs.getEntry(contract_address));
    //std::cout << "Current state: " << eevm::to_hex_string(sMgs) << std::endl;
    //return eevm::from_big_endian(output.data(), output.size());
  
}


int printContractMenu(nlohmann::json& contractHashes) {
    int cnt = 1;
    std::cout << "Contract MENU" << std::endl;
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
    int cnt = 1;
    std::cout << "MAIN MENU"
            << (addresses.size() == 0 ? "(No contracts)" : "") << std::endl;
    for (auto a : addresses) {
        std::cout << cnt << ". " << eevm::address_to_hex_string(a) << std::endl;
        ++cnt;
    }
    std::cout << cnt << ". Deploy new contract"<< std::endl;
    ++cnt;
    std::cout << cnt << ". Exit" << std::endl;
    ++cnt;
    std::cout << cnt << ". Open states" << std::endl;
    ++cnt;
    std::cout << cnt << ". Save states" << std::endl;
    return cnt;


}
template <typename T>
std::string dec2hex(T i)
{
  std::stringstream ss;
  ss << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex
         << i;
  std::string res(ss.str());
  return res;

}

size_t hex2dec(std::string hex_value)
{
  size_t decimal_value;
  std::stringstream ss;
    ss << hex_value; // std::string hex_value
    ss >> std::hex >> decimal_value; // int decimal_value
    return decimal_value;
}
    

void openSavedContracts(
  eevm::SimpleGlobalState& gs,
  std::map<
    eevm::Address,
    std::pair<eevm::Address, nlohmann::basic_json<>::value_type>>& contracts)
{
  auto contracts_path = "_contracts.txt";
  std::ifstream contract_fstream(contracts_path);
  if (!contract_fstream.is_open())
  {
    std::cout << fmt::format(
      "Contracts will not be loaded: Unable to open contract's description "
      "file {}",
      contracts_path);
    return;
  }
  size_t cnt = 0;
  std::string cSize;
  cSize.reserve(18);
  contract_fstream.get(cSize.data(), 19);
  size_t states_count = eevm::to_uint64(cSize);

  while (cnt < states_count)
  {
    std::string addr1;
    addr1.reserve(42);
    std::string addr2;
    addr2.reserve(42);
    std::string cLen;
    cLen.reserve(18);
    contract_fstream.get(addr1.data(), 43);
    //if (addr1.size() == 0)         {
    //  break;
    //}
    contract_fstream.get(addr2.data(), 43);
    contract_fstream.get(cLen.data(), 19);
    std::string contract_string;
    size_t contr_len = eevm::to_uint64(cLen);
    contract_string.resize(contr_len);
    contract_fstream.get(contract_string.data(), contr_len+1);
    auto contract_address = eevm::to_uint256(addr1);
    auto owner_address = eevm::to_uint256(addr2);
    auto contract_def = nlohmann::json::parse(contract_string);
    //if (contracts.find(contract_address) != contracts.end())         {
      contracts.emplace(contract_address, std::make_pair(owner_address, contract_def));
    //}

    ++cnt;
  }
  contract_fstream.close();
  auto state_path = "_states.txt";
  std::ifstream statesStream(state_path);
  if (!statesStream.is_open())
  {
    std::cout << fmt::format(
      "Contracts will not be loaded: Unable to open contract's description "
      "file {}",
      state_path);
    return;
  }
  cnt = 0;
  cSize.clear();
  cSize.reserve(18);
  statesStream.get(cSize.data(), 19);
  states_count = eevm::to_uint64(cSize);
  // Storage translation
  while (cnt < states_count)
  {
    eevm::SimpleGlobalState::StateEntry entry;
    std::string addr;
    addr.resize(42);
    statesStream.get(addr.data(), 43);
    auto addrBin = eevm::to_uint256(addr);
    entry.first.set_address(addrBin);

    std::string bal;
    bal.resize(66);
    statesStream.get(bal.data(), 67);
    entry.first.set_balance(eevm::to_uint256(bal));

    std::string cLen;
    cLen.resize(18);
    statesStream.get(cLen.data(), 19);
    size_t len = eevm::to_uint64(cLen);

    std::string codeRaw;
    codeRaw.resize(len);
    statesStream.get(codeRaw.data(), len + 1u);
    auto codeNet = eevm::to_bytes(codeRaw);
    entry.first.set_code(std::move(codeNet));

    std::string cNonce;
    cNonce.resize(18);
    statesStream.get(cNonce.data(), 19);
    entry.first.set_nonce(eevm::to_uint64(cNonce));
    //Storage from string translation
    std::string cStorageLen;
    cStorageLen.reserve(18);

    statesStream.get(cStorageLen.data(), 19);
    size_t storageLen = eevm::to_uint64(cStorageLen) / 132;
    size_t sCounter = 0;
    while (sCounter < storageLen) {
      std::string sKey;
      sKey.resize(66);
      statesStream.get(sKey.data(), 67);
      std::string sData;
      sData.resize(66);
      statesStream.get(sData.data(), 67);
      entry.second.store(eevm::to_uint256(sKey), eevm::to_uint256(sData));

      ++sCounter;
    }
    if (!gs.exists(addrBin)) {
      gs.insert(entry);
    }
    ++cnt;
  }
  statesStream.close();
}



void saveCurrentContracts(
  eevm::SimpleGlobalState& gs,
  std::map<
    eevm::Address,
    std::pair<eevm::Address, nlohmann::basic_json<>::value_type>>& contracts) {
    auto contracts_path = "_contracts.txt";
  auto ContractsStream = std::ofstream(contracts_path);
  auto fSize = dec2hex(contracts.size());
  ContractsStream << fSize; 
  for (auto cont : contracts)       {
    auto addr1 = eevm::address_to_hex_string(cont.first);
    auto addr2 = eevm::address_to_hex_string(cont.second.first);
    auto contr = cont.second.second.dump();
    auto cSize = dec2hex(contr.size());
    ContractsStream << addr1 
                    << addr2
                    << cSize << contr;
  }
  ContractsStream.close();
  auto state_path = "_states.txt";
  auto statesStream = std::ofstream(state_path);
  auto addrs = gs.getContractAddresses();
  auto aSize = dec2hex(addrs.size());
  statesStream << aSize; 
  for (auto addr : addrs) {
    auto entry = gs.getEntry(addr);
    statesStream << eevm::address_to_hex_string(entry.first.get_address())
                 << eevm::SimpleStorage::to_hex_string_full(entry.first.get_balance());
    auto codeStr = eevm::to_hex_string(entry.first.get_code());
    auto codeLen = dec2hex(codeStr.size());
    auto nonce = entry.first.get_nonce();
    statesStream << codeLen << codeStr
                 << dec2hex(nonce);
    auto storageStr = entry.second.saveToDB();
    auto storageLen = dec2hex(storageStr.size());
    statesStream << storageLen << storageStr;
  }
  statesStream.close();
}


std::vector<std::string> getConstructorParameters(nlohmann::json contactDef) {
  std::vector<std::string> res;
  return res;
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
  if (choice == cnt-2) {

    return 0;
  }
  if (choice == cnt) {
      //save global state
    saveCurrentContracts(gs, contracts);
      return 1;
  }
  if (choice == cnt - 1)
  {
    // save global state
    openSavedContracts(gs, contracts);
    return 1;
  }

  if (choice == cnt - 3) {
    //deploy
    // Create an account at a random address, representing the 'owner' who
    // created
    // the ERC20 contract (gets entire token supply initially)
    const auto owner_address = get_random_address();
    // Open the contract definition file
    std::string contract_path;
    nlohmann::json contract_def;
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
        contract_def = all_contracts["simple"];
        break;
    }



    // Parse the contract definition from file

    std::cout << "Contract will be deployed from: "
              << eevm::address_to_hex_string(owner_address) << std::endl;
    // Create environment
    Environment env{gs, owner_address, contract_def};
    auto contructorParameters = getConstructorParameters(contract_def);

    auto contractHashes = env.contract_definition["hashes"];

    // Deploy the contract
    std::vector<uint256_t> params;
    const auto contract_address = deploy_contract(env, params, 0u, 0u);
    contracts.emplace(
      contract_address, std::make_pair(owner_address, contract_def));
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
