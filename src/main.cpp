#include "rudy/sbom.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <set>
#include <string_view>
#include <vector>

namespace {

struct Arguments {
  std::string output = "text";
  std::vector<std::string> fail_on;
  rudy::sbom::Policy policy;
  std::string baseline;
  std::string candidate;
};

std::string lower(std::string value) {
  for (char& c : value) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  return value;
}

void usage(std::ostream& out) {
  out << "Rudy SBOM Delta 0.1.0\n"
      << "Compare SPDX and CycloneDX JSON inventories offline.\n\n"
      << "Usage: rudy-sbom-delta [options] BASELINE.json CANDIDATE.json\n\n"
      << "Options:\n"
      << "  --format text|json|csv     Output format (default: text)\n"
      << "  --fail-on CATEGORY         Exit 1 if a change occurs; repeat or use comma list\n"
      << "                             added,removed,version,hash,license,any\n"
      << "  --deny-license ID          Reject an exact license identifier in candidate SBOM\n"
      << "  --require-hashes           Reject candidate components without a supported hash\n"
      << "  -h, --help                 Show this help\n"
      << "  --version                  Show version\n\n"
      << "Exit codes: 0 clean, 1 policy/fail-on threshold matched, 2 input or usage error.\n";
}

std::vector<std::string> split_categories(const std::string& input) {
  std::vector<std::string> result;
  std::size_t start = 0;
  while (start <= input.size()) {
    const std::size_t comma = input.find(',', start);
    const std::size_t end = comma == std::string::npos ? input.size() : comma;
    const std::string category = lower(input.substr(start, end - start));
    if (category.empty()) throw std::runtime_error("--fail-on contains an empty category");
    if (category != "added" && category != "removed" && category != "version" &&
        category != "hash" && category != "license" && category != "any")
      throw std::runtime_error("unknown --fail-on category: " + category);
    result.push_back(category);
    if (comma == std::string::npos) break;
    start = comma + 1U;
  }
  return result;
}

Arguments parse_args(int argc, char** argv) {
  Arguments args;
  std::vector<std::string> positional;
  for (int i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    auto take_value = [&](std::string_view option) -> std::string {
      if (i + 1 >= argc) throw std::runtime_error(std::string(option) + " requires a value");
      ++i;
      return argv[i];
    };
    if (arg == "--format") args.output = lower(take_value(arg));
    else if (arg == "--fail-on") {
      auto categories = split_categories(take_value(arg));
      args.fail_on.insert(args.fail_on.end(), categories.begin(), categories.end());
    } else if (arg == "--deny-license") {
      const std::string id = take_value(arg);
      if (id.empty()) throw std::runtime_error("--deny-license cannot be empty");
      args.policy.denied_licenses.push_back(id);
    } else if (arg == "--require-hashes") args.policy.require_hashes = true;
    else if (arg == "--help" || arg == "-h") { usage(std::cout); std::exit(0); }
    else if (arg == "--version") { std::cout << "rudy-sbom-delta 0.1.0\n"; std::exit(0); }
    else if (!arg.empty() && arg.front() == '-') throw std::runtime_error("unknown option: " + std::string(arg));
    else positional.emplace_back(arg);
  }
  if (args.output != "text" && args.output != "json" && args.output != "csv")
    throw std::runtime_error("--format must be text, json, or csv");
  if (positional.size() != 2U) throw std::runtime_error("provide exactly a baseline and candidate SBOM; use --help for usage");
  args.baseline = positional[0];
  args.candidate = positional[1];
  return args;
}

std::string json_escape(const std::string& input) {
  std::string output;
  output.reserve(input.size() + 8U);
  constexpr char hex[] = "0123456789abcdef";
  for (unsigned char c : input) {
    switch (c) {
      case '"': output += "\\\""; break;
      case '\\': output += "\\\\"; break;
      case '\b': output += "\\b"; break;
      case '\f': output += "\\f"; break;
      case '\n': output += "\\n"; break;
      case '\r': output += "\\r"; break;
      case '\t': output += "\\t"; break;
      default:
        if (c < 0x20U) { output += "\\u00"; output.push_back(hex[(c >> 4U) & 0x0FU]); output.push_back(hex[c & 0x0FU]); }
        else output.push_back(static_cast<char>(c));
    }
  }
  return output;
}

std::string csv_escape(const std::string& input) {
  std::string output = "\"";
  for (char c : input) {
    if (c == '"') output += "\"\"";
    else output.push_back(c);
  }
  output.push_back('"');
  return output;
}

std::size_t count_kind(const rudy::sbom::Report& report, rudy::sbom::ChangeKind kind) {
  return static_cast<std::size_t>(std::count_if(report.changes.begin(), report.changes.end(),
    [&](const auto& change) { return change.kind == kind; }));
}

void output_json(const rudy::sbom::Document& baseline, const rudy::sbom::Document& candidate,
                 const rudy::sbom::Report& report) {
  std::cout << "{\"baseline\":{\"format\":\"" << json_escape(baseline.format)
            << "\",\"spec_version\":\"" << json_escape(baseline.spec_version)
            << "\",\"components\":" << baseline.packages.size() << "},\"candidate\":{\"format\":\""
            << json_escape(candidate.format) << "\",\"spec_version\":\"" << json_escape(candidate.spec_version)
            << "\",\"components\":" << candidate.packages.size() << "},\"changes\":[";
  for (std::size_t i = 0; i < report.changes.size(); ++i) {
    const auto& change = report.changes[i];
    if (i != 0U) std::cout << ',';
    std::cout << "{\"kind\":\"" << rudy::sbom::to_string(change.kind) << "\",\"package\":\""
              << json_escape(change.name) << "\",\"identity\":\"" << json_escape(change.identity)
              << "\",\"before\":\"" << json_escape(change.before) << "\",\"after\":\""
              << json_escape(change.after) << "\"}";
  }
  std::cout << "],\"policy_violations\":[";
  for (std::size_t i = 0; i < report.policy_violations.size(); ++i) {
    const auto& violation = report.policy_violations[i];
    if (i != 0U) std::cout << ',';
    std::cout << "{\"rule\":\"" << json_escape(violation.rule) << "\",\"package\":\""
              << json_escape(violation.package) << "\",\"detail\":\"" << json_escape(violation.detail) << "\"}";
  }
  std::cout << "],\"summary\":{\"added\":" << count_kind(report, rudy::sbom::ChangeKind::added)
            << ",\"removed\":" << count_kind(report, rudy::sbom::ChangeKind::removed)
            << ",\"version\":" << count_kind(report, rudy::sbom::ChangeKind::version)
            << ",\"hash\":" << count_kind(report, rudy::sbom::ChangeKind::hash)
            << ",\"license\":" << count_kind(report, rudy::sbom::ChangeKind::license)
            << "}}\n";
}

void output_csv(const rudy::sbom::Report& report) {
  std::cout << "kind,package,identity,before,after\n";
  for (const auto& change : report.changes) {
    std::cout << csv_escape(rudy::sbom::to_string(change.kind)) << ',' << csv_escape(change.name) << ','
              << csv_escape(change.identity) << ',' << csv_escape(change.before) << ',' << csv_escape(change.after) << '\n';
  }
  for (const auto& violation : report.policy_violations) {
    std::cout << csv_escape("policy:" + violation.rule) << ',' << csv_escape(violation.package) << ",,"
              << csv_escape("") << ',' << csv_escape(violation.detail) << '\n';
  }
}

void output_text(const rudy::sbom::Document& baseline, const rudy::sbom::Document& candidate,
                 const rudy::sbom::Report& report) {
  std::cout << "Rudy SBOM Delta  baseline " << baseline.format << ' ' << baseline.spec_version << " ("
            << baseline.packages.size() << ")  ->  candidate " << candidate.format << ' ' << candidate.spec_version
            << " (" << candidate.packages.size() << ")\n\n";
  if (report.changes.empty()) std::cout << "No component changes.\n";
  for (const auto& change : report.changes) {
    std::cout << '[' << rudy::sbom::to_string(change.kind) << "] " << change.name;
    if (change.kind == rudy::sbom::ChangeKind::added) std::cout << "  " << change.after;
    else if (change.kind == rudy::sbom::ChangeKind::removed) std::cout << "  " << change.before;
    else std::cout << "  " << (change.before.empty() ? "(none)" : change.before) << " -> "
                   << (change.after.empty() ? "(none)" : change.after);
    std::cout << "  {" << change.identity << "}\n";
  }
  for (const auto& violation : report.policy_violations)
    std::cout << "[policy:" << violation.rule << "] " << violation.package << "  " << violation.detail << '\n';
  std::cout << "\nSummary: +" << count_kind(report, rudy::sbom::ChangeKind::added)
            << " -" << count_kind(report, rudy::sbom::ChangeKind::removed)
            << " version=" << count_kind(report, rudy::sbom::ChangeKind::version)
            << " hash=" << count_kind(report, rudy::sbom::ChangeKind::hash)
            << " license=" << count_kind(report, rudy::sbom::ChangeKind::license)
            << " policy=" << report.policy_violations.size() << '\n';
}

bool threshold_matched(const rudy::sbom::Report& report, const std::vector<std::string>& fail_on) {
  for (const std::string& category : fail_on) {
    if (category == "any" && !report.changes.empty()) return true;
    for (const auto& change : report.changes) {
      if (rudy::sbom::to_string(change.kind) == category) return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    const Arguments args = parse_args(argc, argv);
    const auto baseline = rudy::sbom::load_document(args.baseline);
    const auto candidate = rudy::sbom::load_document(args.candidate);
    auto report = rudy::sbom::compare(baseline, candidate);
    rudy::sbom::evaluate_policy(report, candidate, args.policy);
    if (args.output == "json") output_json(baseline, candidate, report);
    else if (args.output == "csv") output_csv(report);
    else output_text(baseline, candidate, report);
    return (!report.policy_violations.empty() || threshold_matched(report, args.fail_on)) ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "rudy-sbom-delta: " << error.what() << '\n';
    return 2;
  }
}
