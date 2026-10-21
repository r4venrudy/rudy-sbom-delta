#include "rudy/sbom.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void check(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

std::filesystem::path write_temp(const std::filesystem::path& directory, const std::string& name,
                                 const std::string& contents) {
  const auto path = directory / name;
  std::ofstream output(path, std::ios::binary);
  output << contents;
  if (!output) throw std::runtime_error("could not write test fixture");
  return path;
}

std::size_t count(const rudy::sbom::Report& report, rudy::sbom::ChangeKind kind) {
  std::size_t result = 0;
  for (const auto& change : report.changes) if (change.kind == kind) ++result;
  return result;
}

}  // namespace

int main() {
  const auto directory = std::filesystem::temp_directory_path() / "rudy-sbom-delta-test-fixtures";
  try {
    std::filesystem::create_directories(directory);
    const std::string spdx = R"({
      "spdxVersion":"SPDX-2.3",
      "packages":[
        {"name":"lib-a","versionInfo":"1.0","licenseConcluded":"MIT",
         "checksums":[{"algorithm":"SHA256","checksumValue":"aaa"}],
         "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lib-a@1.0"}]},
        {"name":"gone","versionInfo":"2.0","licenseDeclared":"BSD-3-Clause",
         "checksums":[{"algorithm":"SHA-256","checksumValue":"deadbeef"}]}
      ]
    })";
    const std::string cyclone = R"({
      "bomFormat":"CycloneDX","specVersion":"1.6",
      "metadata":{"component":{"name":"demo-app","version":"4.0","type":"application"}},
      "components":[
        {"type":"library","name":"lib-a","version":"2.0","purl":"pkg:npm/lib-a@2.0",
         "hashes":[{"alg":"SHA-256","content":"BBBB"}],
         "licenses":[{"license":{"id":"Apache-2.0"}}]},
        {"type":"library","name":"new-lib","version":"1.1","purl":"pkg:npm/new-lib@1.1",
         "licenses":[{"expression":"MIT OR Apache-2.0"}],
         "components":[{"type":"library","name":"nested","version":"3"}]}
      ]
    })";
    const auto old_path = write_temp(directory, "old.spdx.json", spdx);
    const auto new_path = write_temp(directory, "new.cdx.json", cyclone);
    const auto old_doc = rudy::sbom::load_document(old_path);
    const auto new_doc = rudy::sbom::load_document(new_path);
    check(old_doc.format == "SPDX" && old_doc.packages.size() == 2U, "SPDX packages were not normalized");
    check(new_doc.format == "CycloneDX" && new_doc.packages.size() == 4U, "CycloneDX root/nested components were not collected");

    const auto report = rudy::sbom::compare(old_doc, new_doc);
    check(count(report, rudy::sbom::ChangeKind::version) == 1U, "version drift should be reported once");
    check(count(report, rudy::sbom::ChangeKind::hash) == 1U, "hash drift should be reported once");
    check(count(report, rudy::sbom::ChangeKind::license) == 1U, "license drift should be reported once");
    check(count(report, rudy::sbom::ChangeKind::removed) == 1U, "removed package should be reported");
    check(count(report, rudy::sbom::ChangeKind::added) == 3U, "new and nested package additions should be reported");

    rudy::sbom::Policy policy;
    policy.denied_licenses = {"Apache-2.0"};
    policy.require_hashes = true;
    auto gated = rudy::sbom::compare(old_doc, new_doc);
    rudy::sbom::evaluate_policy(gated, new_doc, policy);
    check(gated.policy_violations.size() >= 3U, "license and missing-hash policy violations should be found");

    const std::string same_spdx = R"({"spdxVersion":"SPDX-2.3","packages":[
      {"name":"lib-a","versionInfo":"1.0","licenseConcluded":"MIT",
       "checksums":[{"algorithm":"SHA256","checksumValue":"aaa"}],
       "externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/lib-a@1.0"}]}
    ]})";
    const auto same_path = write_temp(directory, "same.spdx.json", same_spdx);
    const auto identical = rudy::sbom::compare(rudy::sbom::load_document(same_path), rudy::sbom::load_document(same_path));
    check(identical.changes.empty(), "identical SBOMs must produce no changes");

    const auto malformed = write_temp(directory, "malformed.json", R"({"spdxVersion":"SPDX-2.3","packages":[],"packages":[]})");
    bool rejected = false;
    try { (void)rudy::sbom::load_document(malformed); }
    catch (const std::runtime_error&) { rejected = true; }
    check(rejected, "duplicate JSON object members must be rejected");

    const auto unsupported = write_temp(directory, "unsupported.json", R"({"spdxVersion":"SPDX-3.0","packages":[]})");
    rejected = false;
    try { (void)rudy::sbom::load_document(unsupported); }
    catch (const std::runtime_error&) { rejected = true; }
    check(rejected, "unsupported SPDX versions must be rejected");

    const auto escaped = write_temp(directory, "unicode.json", R"({"spdxVersion":"SPDX-2.3","packages":[{"name":"lib-\ud83d\ude80"}]})");
    check(rudy::sbom::load_document(escaped).packages.front().name == "lib-\xF0\x9F\x9A\x80",
          "valid surrogate pairs must be decoded as UTF-8");

    std::filesystem::remove_all(directory);
    std::cout << "All Rudy SBOM Delta tests passed.\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "test failure: " << error.what() << '\n';
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
    return 1;
  }
}
