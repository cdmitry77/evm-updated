// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "eEVM/opcode.h"
#include "eEVM/processor.h"
#include "eEVM/simple/simpleglobalstate.h"

#include <fmt/format_header_only.h>
#include <iostream>
#include <fstream>

struct Environment
{
  eevm::GlobalState& gs;
  const eevm::Address& owner_address;
  const nlohmann::json& contract_definition;
};

std::vector<uint8_t> create_bytecode(const std::string& s)
{
  std::vector<uint8_t> code;
  constexpr uint8_t mdest = 0x0;
  const uint8_t rsize = s.size() + 1;

  // Store each byte in evm memory
  uint8_t mcurrent = mdest;
  for (const char& c : s)
  {
    code.push_back(eevm::Opcode::PUSH1);
    code.push_back(c);
    code.push_back(eevm::Opcode::PUSH1);
    code.push_back(mcurrent++);
    code.push_back(eevm::Opcode::MSTORE8);
  }

  // Return
  code.push_back(eevm::Opcode::PUSH1);
  code.push_back(rsize);
  code.push_back(eevm::Opcode::PUSH1);
  code.push_back(mdest);
  code.push_back(eevm::Opcode::RETURN);

  return code;
}


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

eevm::Address deploy_contract(
  Environment& env)
{
  // Generate the contract address
  const auto contract_address = eevm::generate_address(env.owner_address, 0u);

  // Get the binary constructor of the contract
  auto contract_constructor = eevm::to_bytes(env.contract_definition["bin"]);

  // The constructor takes a single argument (total_supply) - append it
  //append_argument(contract_constructor, total_supply);

  // Set this constructor as the contract's code body
  auto contract = env.gs.create(contract_address, 0u, contract_constructor);

  // Run a transaction to initialise this account
  auto result =
    run_and_check_result(env, env.owner_address, contract_address, {});

  // Result of running the compiled constructor is the code that should be the
  // contract's body (constructor will also have setup contract's Storage)
  contract.acc.set_code(std::move(result));

  return contract.acc.get_address();
}


uint256_t get_value(
  Environment& env,
  const eevm::Address& contract_address)
{
  // Anyone can call balanceOf - prove this by asking from a randomly generated
  // address
  const auto caller = get_random_address();

  auto function_call =
    eevm::to_bytes(env.contract_definition["hashes"]["get_a()"]);

  //append_argument(function_call, target_address);

  const auto output =
    run_and_check_result(env, caller, contract_address, function_call);

  return eevm::from_big_endian(output.data(), output.size());
}

eevm::Code execute(Environment& env, const eevm::Address& contract_address, std::string methodName, std::string params)
{
  (void) params;
  // Anyone can call balanceOf - prove this by asking from a randomly generated
  // address
  const auto caller = get_random_address();

  auto function_call =
    eevm::to_bytes(env.contract_definition["hashes"][methodName]);

  // append_argument(function_call, target_address);

  const auto output =
    run_and_check_result(env, caller, contract_address, function_call);

  return output;
}

uint256_t inc_value(Environment& env, const eevm::Address& contract_address)
{
  // Anyone can call balanceOf - prove this by asking from a randomly generated
  // address
  const auto caller = get_random_address();

  auto function_call =
    eevm::to_bytes(env.contract_definition["hashes"]["inc_a()"]);

  // append_argument(function_call, target_address);

  const auto output =
    run_and_check_result(env, caller, contract_address, function_call);

  return eevm::from_big_endian(output.data(), output.size());
}

uint256_t dec_value(Environment& env, const eevm::Address& contract_address)
{
  // Anyone can call balanceOf - prove this by asking from a randomly generated
  // address
  const auto caller = get_random_address();

  auto function_call =
    eevm::to_bytes(env.contract_definition["hashes"]["dec_a()"]);

  // append_argument(function_call, target_address);

  const auto output =
    run_and_check_result(env, caller, contract_address, function_call);

  return eevm::from_big_endian(output.data(), output.size());
}

int main(int argc, char** argv)
{
  (void) argc;
  (void) argv;
  //std::string a;
  //std::cin >> a;
  // Create random addresses for sender and contract
  std::cout << "Starting process" << std::endl;

  std::vector<uint8_t> raw_address(20);
  std::generate(
    raw_address.begin(), raw_address.end(), []() { return rand(); });
  const eevm::Address owner_address =
    eevm::from_big_endian(raw_address.data(), raw_address.size());

  std::generate(
    raw_address.begin(), raw_address.end(), []() { return rand(); });
  //const eevm::Address to =
    //eevm::from_big_endian(raw_address.data(), raw_address.size());

  const auto contract_path = "contract.json";
  std::ifstream contract_fstream(contract_path);
  if (!contract_fstream)
  {
    throw std::runtime_error(
    fmt::format("Unable to open contract definition file {}", contract_path));
  }

  // Parse the contract definition from file
  std::cout << "Parsing contract: start" << std::endl;
  const auto contracts_definition = nlohmann::json::parse(contract_fstream);
  const auto all_contracts = contracts_definition["contract"];
  const auto erc20_definition = all_contracts["simple"];
  //std::cout << "bin = " << erc20_definition["bin"] << std::endl;
  //std::string hString = "";
  //for (auto a : erc20_definition["hashes"])
  //{
  //  hString += a + "\n";
  //}
  //std::cout << "hashes:" << std::endl
  //          << hString << std::endl;
  std::cout << "Parsing contract: finish" << std::endl;


   // Create global state
  eevm::SimpleGlobalState gs;
  std::cout << "State created" << std::endl;

   // Create environment  
  Environment env{gs, owner_address, erc20_definition};
  std::cout << "Environment created" << std::endl;

    // Deploy the contract
  const auto contract_address = deploy_contract(env);
  auto r = get_value(env, contract_address);
  //auto res1 = eevm::from_big_endian(r.output.data(), r.output.size());
  std::cout << "Initial value = " << eevm::to_lower_hex_string(r) << std::endl;
  auto r1 = inc_value(env, contract_address);
  std::cout << " ... + 1 = " << eevm::to_lower_hex_string(r1) << std::endl;
  auto r2 = inc_value(env, contract_address);
  std::cout << " ... + 1 = " << eevm::to_lower_hex_string(r2) << std::endl;
  auto r3 = dec_value(env, contract_address);
  std::cout << " ... - 1 = " << eevm::to_lower_hex_string(r3) << std::endl;
  // Create code
  //std::string hello_world("Hello world!");
  //const std::string hex_code =
  //  "6060604052341561000c57fe5b5b60016000819055505b5b610127806100266000396000f30060606040526000357c0100000000000000000000000000000000000000000000000000000000900463ffffffff1680634815918114604e5780634995773c14607157806391f82161146094575bfe5b3415605557fe5b605b60b7565b6040518082815260200191505060405180910390f35b3415607857fe5b607e60c2565b6040518082815260200191505060405180910390f35b3415609b57fe5b60a160e4565b6040518082815260200191505060405180910390f35b600060005490505b90565b60006001600054111560db576001600054036000819055505b60005490505b90565b600060016000540160008190555060005490505b905600a165627a7a723058200b31841e93ee98d57b4f2181cbe12f6de9ea17a5fb3d6de66ec8acc07a5a53eb0029";

  //const eevm::Code code = eevm::to_bytes(hex_code);//create_bytecode(hello_world);

  // Deploy contract to global state
  //const eevm::AccountState contract = gs.create(to, 0, code);

  // Create transaction
  //eevm::NullLogHandler ignore;
  //eevm::Transaction tx(sender, ignore);

  // Create processor
  //eevm::Processor p(gs);
  //auto function_get = eevm::to_bytes("48159181");
  //auto function_inc = eevm::to_bytes("4995773c");
  //auto function_dec = eevm::to_bytes("91f82162");
  // Execute code. All execution is associated with a transaction. This
  // transaction is called by sender, executing the code in contract, with empty
  // input (and no trace collection)
  //for (int i = 0; i < 10; ++i)
  //{
  //  const eevm::ExecResult e =
  //    p.run(tx, sender, contract, function_inc, 0, nullptr);

  //  // Check the response
  //  if (e.er != eevm::ExitReason::returned)
  //  {
  //    std::cout << fmt::format("Unexpected return code: {}", (size_t)e.er)
  //              << std::endl;
  //    return 2;
  //  }

  //  auto outp = eevm::from_big_endian(e.output.data(), e.output.size());
  //  // Create string from response data, and print it
  //  const std::string response(eevm::to_lower_hex_string(outp));
  //  // if (response != hello_world)
  //  //{
  //  //  throw std::runtime_error(fmt::format(
  //  //    "Incorrect result.\n Expected: {}\n Actual: {}", hello_world,
  //  //    response));
  //  //  return 3;
  //  //}

  //  std::cout << response << std::endl;
  //}
  return 0;
}
