#include "rudy/sbom.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <system_error>
#include <tuple>
#include <variant>

namespace rudy::sbom {
namespace {

constexpr std::size_t kMaxInputBytes = 64U * 1024U * 1024U;
constexpr std::size_t kMaxJsonNodes = 1'000'000U;
constexpr std::size_t kMaxPackages = 250'000U;
constexpr unsigned kMaxJsonDepth = 128U;

struct Number { std::string raw; };
struct Json {
  using Array = std::vector<Json>;
  using Object = std::map<std::string, Json, std::less<>>;
  std::variant<std::nullptr_t, bool, Number, std::string, Array, Object> value;
};

class JsonParser {
 public:
  explicit JsonParser(const std::string& input) : input_(input) {}

  Json parse() {
    skip_space();
    Json value = parse_value(0U);
    skip_space();
    if (position_ != input_.size()) fail("trailing data after JSON value");
    return value;
  }

 private:
  [[noreturn]] void fail(const std::string& message) const {
    throw std::runtime_error("invalid JSON at byte " + std::to_string(position_) + ": " + message);
  }

  void skip_space() {
    while (position_ < input_.size()) {
      const char c = input_[position_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++position_;
      else break;
    }
  }

  bool consume(char expected) {
    if (position_ < input_.size() && input_[position_] == expected) {
      ++position_;
      return true;
    }
    return false;
  }

  void require(char expected) {
    if (!consume(expected)) fail(std::string("expected '") + expected + "'");
  }

  Json parse_value(unsigned depth) {
    if (depth > kMaxJsonDepth) fail("maximum nesting depth exceeded");
    if (++nodes_ > kMaxJsonNodes) fail("maximum JSON node count exceeded");
    skip_space();
    if (position_ >= input_.size()) fail("unexpected end of input");
    const char c = input_[position_];
    if (c == '{') return parse_object(depth + 1U);
    if (c == '[') return parse_array(depth + 1U);
    if (c == '"') return Json{parse_string()};
    if (c == 't') { literal("true"); return Json{true}; }
    if (c == 'f') { literal("false"); return Json{false}; }
    if (c == 'n') { literal("null"); return Json{nullptr}; }
    if (c == '-' || (c >= '0' && c <= '9')) return Json{parse_number()};
    fail("unexpected token");
  }

  void literal(std::string_view expected) {
    if (input_.compare(position_, expected.size(), expected) != 0) fail("invalid literal");
    position_ += expected.size();
  }

  static void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7FU) out.push_back(static_cast<char>(cp));
    else if (cp <= 0x7FFU) {
      out.push_back(static_cast<char>(0xC0U | (cp >> 6U)));
      out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    } else if (cp <= 0xFFFFU) {
      out.push_back(static_cast<char>(0xE0U | (cp >> 12U)));
      out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    } else {
      out.push_back(static_cast<char>(0xF0U | (cp >> 18U)));
      out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3FU)));
      out.push_back(static_cast<char>(0x80U | (cp & 0x3FU)));
    }
  }

  std::uint16_t parse_hex_quad() {
    if (input_.size() - position_ < 4U) fail("incomplete Unicode escape");
    std::uint16_t value = 0;
    for (unsigned i = 0; i < 4U; ++i) {
      const char c = input_[position_++];
      unsigned digit = 0;
      if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = 10U + static_cast<unsigned>(c - 'a');
      else if (c >= 'A' && c <= 'F') digit = 10U + static_cast<unsigned>(c - 'A');
      else fail("invalid Unicode escape");
      value = static_cast<std::uint16_t>((value << 4U) | digit);
    }
    return value;
  }

  std::string parse_string() {
    require('"');
    std::string result;
    while (position_ < input_.size()) {
      const unsigned char c = static_cast<unsigned char>(input_[position_++]);
      if (c == '"') return result;
      if (c < 0x20U) fail("unescaped control character in string");
      if (c != '\\') { result.push_back(static_cast<char>(c)); continue; }
      if (position_ >= input_.size()) fail("incomplete escape sequence");
      const char escaped = input_[position_++];
      switch (escaped) {
        case '"': result.push_back('"'); break;
        case '\\': result.push_back('\\'); break;
        case '/': result.push_back('/'); break;
        case 'b': result.push_back('\b'); break;
        case 'f': result.push_back('\f'); break;
        case 'n': result.push_back('\n'); break;
        case 'r': result.push_back('\r'); break;
        case 't': result.push_back('\t'); break;
        case 'u': {
          const std::uint16_t first = parse_hex_quad();
          std::uint32_t cp = first;
          if (first >= 0xD800U && first <= 0xDBFFU) {
            if (input_.size() - position_ < 2U || input_[position_] != '\\' || input_[position_ + 1U] != 'u')
              fail("high surrogate without low surrogate");
            position_ += 2U;
            const std::uint16_t second = parse_hex_quad();
            if (second < 0xDC00U || second > 0xDFFFU) fail("invalid low surrogate");
            cp = 0x10000U + ((static_cast<std::uint32_t>(first) - 0xD800U) << 10U) +
                 (static_cast<std::uint32_t>(second) - 0xDC00U);
          } else if (first >= 0xDC00U && first <= 0xDFFFU) {
            fail("low surrogate without high surrogate");
          }
          append_utf8(result, cp);
          break;
        }
        default: fail("invalid escape sequence");
      }
    }
    fail("unterminated string");
  }

  Number parse_number() {
    const std::size_t begin = position_;
    consume('-');
    if (consume('0')) {
      if (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9')
        fail("leading zero in number");
    } else {
      if (position_ >= input_.size() || input_[position_] < '1' || input_[position_] > '9')
        fail("invalid number");
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
    }
    if (consume('.')) {
      const std::size_t fraction = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
      if (fraction == position_) fail("missing digits after decimal point");
    }
    if (position_ < input_.size() && (input_[position_] == 'e' || input_[position_] == 'E')) {
      ++position_;
      if (position_ < input_.size() && (input_[position_] == '+' || input_[position_] == '-')) ++position_;
      const std::size_t exponent = position_;
      while (position_ < input_.size() && input_[position_] >= '0' && input_[position_] <= '9') ++position_;
      if (exponent == position_) fail("missing digits in exponent");
    }
    return Number{input_.substr(begin, position_ - begin)};
  }

  Json parse_array(unsigned depth) {
    require('[');
    Json::Array values;
    skip_space();
    if (consume(']')) return Json{std::move(values)};
    while (true) {
      values.push_back(parse_value(depth));
      skip_space();
      if (consume(']')) return Json{std::move(values)};
      require(',');
    }
  }

  Json parse_object(unsigned depth) {
    require('{');
    Json::Object values;
    skip_space();
    if (consume('}')) return Json{std::move(values)};
    while (true) {
      skip_space();
      if (position_ >= input_.size() || input_[position_] != '"') fail("object key must be a string");
      std::string key = parse_string();
      skip_space();
      require(':');
      Json value = parse_value(depth);
      if (!values.emplace(std::move(key), std::move(value)).second) fail("duplicate object key");
      skip_space();
      if (consume('}')) return Json{std::move(values)};
      require(',');
    }
  }

  const std::string& input_;
  std::size_t position_ = 0;
  std::size_t nodes_ = 0;
};

const Json* member(const Json& value, std::string_view key) {
  const auto* object = std::get_if<Json::Object>(&value.value);
  if (!object) return nullptr;
  const auto it = object->find(key);
  return it == object->end() ? nullptr : &it->second;
}

const Json::Array* array(const Json* value) {
  return value ? std::get_if<Json::Array>(&value->value) : nullptr;
}

std::string string_value(const Json* value) {
  if (!value) return {};
  const auto* text = std::get_if<std::string>(&value->value);
  return text ? *text : std::string{};
}

std::string field(const Json& value, std::string_view key) {
  return string_value(member(value, key));
}

std::string trim(std::string value) {
  const auto not_space = [](unsigned char c) { return std::isspace(c) == 0; };
  const auto begin = std::find_if(value.begin(), value.end(), [&](char c) { return not_space(static_cast<unsigned char>(c)); });
  const auto end = std::find_if(value.rbegin(), value.rend(), [&](char c) { return not_space(static_cast<unsigned char>(c)); }).base();
  if (begin >= end) return {};
  return std::string(begin, end);
}

std::string lower_ascii(std::string value) {
  for (char& c : value) {
    const auto byte = static_cast<unsigned char>(c);
    if (byte >= 'A' && byte <= 'Z') c = static_cast<char>(byte - 'A' + 'a');
  }
  return value;
}

std::string purl_identity(std::string purl) {
  purl = trim(std::move(purl));
  const std::size_t query = purl.find('?');
  const std::size_t fragment = purl.find('#');
  const std::size_t suffix = std::min(query == std::string::npos ? purl.size() : query,
                                      fragment == std::string::npos ? purl.size() : fragment);
  const std::size_t slash = suffix == 0U ? std::string::npos : purl.rfind('/', suffix - 1U);
  const std::size_t at = purl.rfind('@', suffix);
  if (at != std::string::npos && at < suffix && (slash == std::string::npos || at > slash))
    purl.erase(at, suffix - at);
  return lower_ascii(std::move(purl));
}

std::string package_identity(const std::string& purl, const std::string& name) {
  if (!purl.empty()) {
    const std::string identity = purl_identity(purl);
    if (!identity.empty()) return identity;
  }
  return "name:" + lower_ascii(trim(name));
}

std::string selected_hash(const Json* hashes, bool spdx) {
  const auto* values = array(hashes);
  if (!values) return {};
  std::string fallback;
  for (const Json& item : *values) {
    const std::string algorithm = field(item, spdx ? "algorithm" : "alg");
    std::string content = field(item, spdx ? "checksumValue" : "content");
    if (content.empty()) continue;
    std::string normalized_algorithm = lower_ascii(algorithm);
    normalized_algorithm.erase(std::remove(normalized_algorithm.begin(), normalized_algorithm.end(), '-'), normalized_algorithm.end());
    if (normalized_algorithm == "sha256") return "sha256:" + lower_ascii(std::move(content));
    if (fallback.empty()) fallback = normalized_algorithm + ":" + lower_ascii(std::move(content));
  }
  return fallback;
}

std::string spdx_license(const Json& package) {
  std::string value = field(package, "licenseConcluded");
  if (value.empty() || value == "NOASSERTION" || value == "NONE") value = field(package, "licenseDeclared");
  if (value == "NOASSERTION" || value == "NONE") return {};
  return trim(std::move(value));
}

std::string cyclone_license(const Json* licenses) {
  const auto* values = array(licenses);
  if (!values) return {};
  std::vector<std::string> names;
  for (const Json& entry : *values) {
    std::string expression = field(entry, "expression");
    const Json* license = member(entry, "license");
    if (expression.empty() && license) {
      expression = field(*license, "id");
      if (expression.empty()) expression = field(*license, "name");
    }
    expression = trim(std::move(expression));
    if (!expression.empty()) names.push_back(std::move(expression));
  }
  std::sort(names.begin(), names.end());
  names.erase(std::unique(names.begin(), names.end()), names.end());
  std::string result;
  for (const auto& name : names) {
    if (!result.empty()) result += "; ";
    result += name;
  }
  return result;
}

std::string spdx_purl(const Json& package) {
  const auto* references = array(member(package, "externalRefs"));
  if (!references) return {};
  for (const Json& ref : *references) {
    std::string type = lower_ascii(field(ref, "referenceType"));
    if (type == "purl" || type.find("package-url") != std::string::npos) {
      const std::string locator = field(ref, "referenceLocator");
      if (!locator.empty()) return locator;
    }
  }
  return {};
}

Package parse_spdx_package(const Json& source) {
  Package package;
  package.name = trim(field(source, "name"));
  if (package.name.empty()) throw std::runtime_error("SPDX package is missing its name");
  package.version = trim(field(source, "versionInfo"));
  package.license = spdx_license(source);
  package.hash = selected_hash(member(source, "checksums"), true);
  package.identity = package_identity(spdx_purl(source), package.name);
  return package;
}

Package parse_cyclone_component(const Json& source) {
  Package package;
  package.name = trim(field(source, "name"));
  if (package.name.empty()) throw std::runtime_error("CycloneDX component is missing its name");
  package.version = trim(field(source, "version"));
  package.license = cyclone_license(member(source, "licenses"));
  package.hash = selected_hash(member(source, "hashes"), false);
  const std::string purl = field(source, "purl");
  const std::string bom_ref = field(source, "bom-ref");
  package.identity = package_identity(purl, package.name);
  // bom-ref is intentionally not used as identity: generators often make it unstable between builds.
  (void)bom_ref;
  return package;
}

void add_package(Document& document, Package package) {
  if (document.packages.size() >= kMaxPackages) throw std::runtime_error("SBOM exceeds the 250,000 component limit");
  document.packages.push_back(std::move(package));
}

void collect_cyclone_components(Document& document, const Json* components, unsigned depth) {
  if (depth > kMaxJsonDepth) throw std::runtime_error("CycloneDX component nesting exceeds the supported limit");
  const auto* values = array(components);
  if (!values) return;
  for (const Json& component : *values) {
    add_package(document, parse_cyclone_component(component));
    collect_cyclone_components(document, member(component, "components"), depth + 1U);
  }
}

std::string read_bounded(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) throw std::runtime_error("cannot open input file: " + path.string());
  std::string contents;
  contents.reserve(64U * 1024U);
  std::array<char, 64U * 1024U> buffer{};
  while (input) {
    input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    const auto count = input.gcount();
    if (count > 0) {
      const auto bytes = static_cast<std::size_t>(count);
      if (contents.size() > kMaxInputBytes - bytes) throw std::runtime_error("input exceeds the 64 MiB safety limit");
      contents.append(buffer.data(), bytes);
    }
  }
  if (!input.eof()) throw std::runtime_error("failed while reading input file: " + path.string());
  return contents;
}

bool valid_spdx_version(const std::string& version) {
  return version == "SPDX-2.2" || version.starts_with("SPDX-2.2.") ||
         version == "SPDX-2.3" || version.starts_with("SPDX-2.3.");
}

int change_score(const Package& left, const Package& right) {
  return static_cast<int>(left.version != right.version) + static_cast<int>(left.hash != right.hash) +
         static_cast<int>(left.license != right.license) + static_cast<int>(left.name != right.name);
}

auto package_order(const Package& p) {
  return std::tie(p.version, p.hash, p.license, p.name);
}

bool contains_license(const std::string& expression, const std::string& denied) {
  const std::string target = lower_ascii(denied);
  std::string token;
  auto check = [&]() {
    const bool found = lower_ascii(token) == target;
    token.clear();
    return found;
  };
  for (unsigned char c : expression) {
    const bool identifier = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '+';
    if (identifier) token.push_back(static_cast<char>(c));
    else if (check()) return true;
  }
  return check();
}

}  // namespace

Document load_document(const std::filesystem::path& path) {
  const std::string contents = read_bounded(path);
  const Json root = JsonParser(contents).parse();
  if (!std::holds_alternative<Json::Object>(root.value)) throw std::runtime_error("SBOM root must be a JSON object");

  Document document;
  const std::string spdx_version = field(root, "spdxVersion");
  const std::string bom_format = field(root, "bomFormat");
  if (valid_spdx_version(spdx_version)) {
    document.format = "SPDX";
    document.spec_version = spdx_version;
    const auto* packages = array(member(root, "packages"));
    if (!packages) throw std::runtime_error("SPDX document must contain a packages array");
    if (packages->size() > kMaxPackages) throw std::runtime_error("SBOM exceeds the 250,000 component limit");
    for (const Json& package : *packages) add_package(document, parse_spdx_package(package));
    return document;
  }
  if (bom_format == "CycloneDX") {
    document.format = "CycloneDX";
    document.spec_version = field(root, "specVersion");
    if (document.spec_version != "1.4" && document.spec_version != "1.5" &&
        document.spec_version != "1.6" && document.spec_version != "1.7")
      throw std::runtime_error("supported CycloneDX JSON specVersion values are 1.4 through 1.7");
    const Json* metadata = member(root, "metadata");
    if (metadata) {
      const Json* root_component = member(*metadata, "component");
      if (root_component) add_package(document, parse_cyclone_component(*root_component));
    }
    collect_cyclone_components(document, member(root, "components"), 0U);
    if (document.packages.empty()) throw std::runtime_error("CycloneDX document contains no supported components");
    return document;
  }
  throw std::runtime_error("unsupported SBOM: expected SPDX 2.2/2.3 or CycloneDX JSON 1.4-1.7");
}

Report compare(const Document& baseline, const Document& candidate) {
  using Groups = std::map<std::string, std::vector<Package>, std::less<>>;
  Groups old_groups;
  Groups new_groups;
  for (const auto& package : baseline.packages) old_groups[package.identity].push_back(package);
  for (const auto& package : candidate.packages) new_groups[package.identity].push_back(package);
  for (auto& [key, packages] : old_groups) { (void)key; std::sort(packages.begin(), packages.end(), [](const auto& a, const auto& b) { return package_order(a) < package_order(b); }); }
  for (auto& [key, packages] : new_groups) { (void)key; std::sort(packages.begin(), packages.end(), [](const auto& a, const auto& b) { return package_order(a) < package_order(b); }); }

  std::set<std::string, std::less<>> identities;
  for (const auto& [key, packages] : old_groups) { (void)packages; identities.insert(key); }
  for (const auto& [key, packages] : new_groups) { (void)packages; identities.insert(key); }

  Report report;
  for (const std::string& identity : identities) {
    const auto old_it = old_groups.find(identity);
    const auto new_it = new_groups.find(identity);
    const std::vector<Package> empty;
    const auto& old_packages = old_it == old_groups.end() ? empty : old_it->second;
    const auto& new_packages = new_it == new_groups.end() ? empty : new_it->second;
    std::vector<bool> old_used(old_packages.size(), false);
    std::vector<bool> new_used(new_packages.size(), false);
    std::vector<std::pair<std::size_t, std::size_t>> pairs;

    for (std::size_t oi = 0; oi < old_packages.size(); ++oi) {
      for (std::size_t ni = 0; ni < new_packages.size(); ++ni) {
        if (!new_used[ni] && change_score(old_packages[oi], new_packages[ni]) == 0) {
          old_used[oi] = true;
          new_used[ni] = true;
          pairs.emplace_back(oi, ni);
          break;
        }
      }
    }
    for (std::size_t oi = 0; oi < old_packages.size(); ++oi) {
      if (old_used[oi]) continue;
      std::size_t best = new_packages.size();
      int best_score = 5;
      for (std::size_t ni = 0; ni < new_packages.size(); ++ni) {
        if (new_used[ni]) continue;
        const int score = change_score(old_packages[oi], new_packages[ni]);
        if (score < best_score) { best = ni; best_score = score; }
      }
      if (best != new_packages.size()) {
        old_used[oi] = true;
        new_used[best] = true;
        pairs.emplace_back(oi, best);
      }
    }

    for (const auto& [oi, ni] : pairs) {
      const Package& before = old_packages[oi];
      const Package& after = new_packages[ni];
      if (before.version != after.version) report.changes.push_back({ChangeKind::version, identity, after.name, before.version, after.version});
      if (before.hash != after.hash) report.changes.push_back({ChangeKind::hash, identity, after.name, before.hash, after.hash});
      if (before.license != after.license) report.changes.push_back({ChangeKind::license, identity, after.name, before.license, after.license});
    }
    for (std::size_t oi = 0; oi < old_packages.size(); ++oi) {
      if (!old_used[oi]) report.changes.push_back({ChangeKind::removed, identity, old_packages[oi].name, old_packages[oi].version, {}});
    }
    for (std::size_t ni = 0; ni < new_packages.size(); ++ni) {
      if (!new_used[ni]) report.changes.push_back({ChangeKind::added, identity, new_packages[ni].name, {}, new_packages[ni].version});
    }
  }
  const auto order = [](const Change& a, const Change& b) {
    return std::tie(a.identity, a.kind, a.name, a.before, a.after) < std::tie(b.identity, b.kind, b.name, b.before, b.after);
  };
  std::sort(report.changes.begin(), report.changes.end(), order);
  return report;
}

void evaluate_policy(Report& report, const Document& candidate, const Policy& policy) {
  std::set<std::tuple<std::string, std::string, std::string>> seen;
  for (const Package& package : candidate.packages) {
    if (policy.require_hashes && package.hash.empty()) {
      const auto item = std::make_tuple("require-hash", package.identity, "no supported checksum is recorded");
      if (seen.insert(item).second) report.policy_violations.push_back({std::get<0>(item), package.name, std::get<2>(item)});
    }
    for (const std::string& denied : policy.denied_licenses) {
      if (contains_license(package.license, denied)) {
        const std::string detail = "candidate declares denied license " + denied;
        const auto item = std::make_tuple("deny-license", package.identity, detail);
        if (seen.insert(item).second) report.policy_violations.push_back({std::get<0>(item), package.name, std::get<2>(item)});
      }
    }
  }
  std::sort(report.policy_violations.begin(), report.policy_violations.end(), [](const auto& a, const auto& b) {
    return std::tie(a.rule, a.package, a.detail) < std::tie(b.rule, b.package, b.detail);
  });
}

std::string to_string(ChangeKind kind) {
  switch (kind) {
    case ChangeKind::added: return "added";
    case ChangeKind::removed: return "removed";
    case ChangeKind::version: return "version";
    case ChangeKind::hash: return "hash";
    case ChangeKind::license: return "license";
  }
  return "unknown";
}

}  // namespace rudy::sbom
