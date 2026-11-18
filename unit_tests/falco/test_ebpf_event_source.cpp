// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gtest/gtest.h>

#include <falco_common.h>
#include <falco_engine.h>

#include <fstream>
#include <memory>
#include <sstream>
#include <string>

namespace {

// The unit-test build does not load the container plugin. Provide the fields
// used by the eBPF rule so the actual shipped rule can be compiled here.
class test_container_filtercheck : public sinsp_filter_check {
public:
	test_container_filtercheck() { m_info = &s_info; }
	test_container_filtercheck(const test_container_filtercheck&):
	        test_container_filtercheck() {}

	std::unique_ptr<sinsp_filter_check> allocate_new() override {
		return std::make_unique<test_container_filtercheck>(*this);
	}

protected:
	bool extract_nocache(sinsp_evt*,
	                     std::vector<extract_value_t>&,
	                     std::vector<extract_offset_t>* = nullptr) override {
		return false;
	}

private:
	static const filtercheck_field_info s_fields[];
	static const filter_check_info s_info;
};

const filtercheck_field_info test_container_filtercheck::s_fields[] = {
        {PT_CHARBUF, EPF_NONE, PF_NA, "container.id", "", "Container ID"},
        {PT_CHARBUF, EPF_NONE, PF_NA, "container.name", "", "Container name"},
        {PT_CHARBUF,
         EPF_NONE,
         PF_NA,
         "container.image.repository",
         "",
         "Container image repository"},
};

const filter_check_info test_container_filtercheck::s_info = {
        "container",
        "",
        "Test container metadata",
        3,
        test_container_filtercheck::s_fields,
        filter_check_info::FL_NONE,
};

struct test_engine {
	test_engine() {
		m_filterchecks.add_filter_check(std::make_unique<test_container_filtercheck>());
		m_filter_factory = std::make_shared<sinsp_filter_factory>(&m_inspector, m_filterchecks);
		m_formatter_factory =
		        std::make_shared<sinsp_evt_formatter_factory>(&m_inspector, m_filterchecks);
		m_engine.add_source(falco_common::syscall_source,
		                    m_filter_factory,
		                    m_formatter_factory);
		m_engine.add_source(falco_common::ebpf_source,
		                    m_filter_factory,
		                    m_formatter_factory);
	}

	std::string read_rules() {
		std::ifstream in(TEST_FALCO_EBPF_RULES_FILE);
		std::stringstream content;
		content << in.rdbuf();
		return content.str();
	}

	sinsp m_inspector;
	sinsp_filter_check_list m_filterchecks;
	std::shared_ptr<sinsp_filter_factory> m_filter_factory;
	std::shared_ptr<sinsp_evt_formatter_factory> m_formatter_factory;
	falco_engine m_engine;
};

bool json_array_contains(const nlohmann::json& values, const std::string& expected) {
	for(const auto& value : values) {
		if(value == expected) {
			return true;
		}
	}
	return false;
}

}  // namespace

TEST(EbpfEventSource, classifies_all_supported_bpf_event_abis) {
	EXPECT_TRUE(falco_common::is_ebpf_event(PPME_SYSCALL_BPF_E));
	EXPECT_TRUE(falco_common::is_ebpf_event(PPME_SYSCALL_BPF_X));
	EXPECT_TRUE(falco_common::is_ebpf_event(PPME_SYSCALL_BPF_2_E));
	EXPECT_TRUE(falco_common::is_ebpf_event(PPME_SYSCALL_BPF_2_X));
	EXPECT_FALSE(falco_common::is_ebpf_event(PPME_SYSCALL_OPENAT_E));
	EXPECT_EQ(falco_common::ebpf_event_codes().size(), 4);
}

TEST(EbpfEventSource, shipped_rule_loads_and_uses_the_ebpf_source) {
	test_engine engine;
	const auto rules = engine.read_rules();
	ASSERT_FALSE(rules.empty());

	falco::load_result::rules_contents_t contents = {
	        {"falco-ebpf_rules.yaml", rules}};
	auto result = engine.m_engine.load_rules(rules, "falco-ebpf_rules.yaml");
	ASSERT_TRUE(result->successful()) << result->as_string(true, contents);
	const std::string ruleset = "ebpf-test-ruleset";
	engine.m_engine.enable_rule("", true, ruleset);

	auto event_codes =
	        engine.m_engine.event_codes_for_ruleset(falco_common::ebpf_source, ruleset);
	for(const auto code : falco_common::ebpf_event_codes()) {
		EXPECT_TRUE(event_codes.contains(code))
		        << "missing event code " << static_cast<int>(code);
	}

	auto sc_codes = engine.m_engine.sc_codes_for_ruleset(falco_common::ebpf_source, ruleset);
	EXPECT_TRUE(sc_codes.contains(PPM_SC_BPF));

	std::string rule_name = "eBPF Program Loaded in Container";
	auto description = engine.m_engine.describe_rule(&rule_name, {});
	const auto& rule = description["rules"][0];
	EXPECT_EQ(rule["info"]["source"], falco_common::ebpf_source);
	EXPECT_EQ(rule["info"]["priority"], "Warning");

	const auto& events = rule["details"]["events"];
	EXPECT_TRUE(json_array_contains(events, "bpf"));
	EXPECT_FALSE(json_array_contains(events, "pluginevent"));

	const auto& fields = rule["details"]["output_fields"];
	EXPECT_TRUE(json_array_contains(fields, "proc.name"));
	EXPECT_TRUE(json_array_contains(fields, "evt.arg.cmd"));
	EXPECT_TRUE(json_array_contains(fields, "container.id"));
	EXPECT_TRUE(json_array_contains(fields, "container.image.repository"));
}
