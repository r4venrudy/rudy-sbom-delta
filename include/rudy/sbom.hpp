#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace rudy::sbom {

struct Package {
  std::string identity;
  std::string name;
  std::string version;
  std::string license;
  std::string hash;
};

struct Document {
  std::string format;
  std::string spec_version;
  std::vector<Package> packages;
};

enum class ChangeKind { added, removed, version, hash, license };

struct Change {
  ChangeKind kind;
  std::string identity;
  std::string name;
  std::string before;
  std::string after;
};

struct PolicyViolation {
  std::string rule;
  std::string package;
  std::string detail;
};

struct Policy {
  std::vector<std::string> denied_licenses;
  bool require_hashes = false;
};

struct Report {
  std::vector<Change> changes;
  std::vector<PolicyViolation> policy_violations;
};

Document load_document(const std::filesystem::path& path);
Report compare(const Document& baseline, const Document& candidate);
void evaluate_policy(Report& report, const Document& candidate, const Policy& policy);
std::string to_string(ChangeKind kind);

}  // namespace rudy::sbom
