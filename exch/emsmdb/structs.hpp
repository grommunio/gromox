#pragma once
#include <cstdint>

struct progress_information {
	uint16_t version = 0, padding1 = 0, padding2 = 0;
	uint32_t fai_count = 0, normal_count = 0;
	uint64_t fai_size = 0, normal_size = 0;
};
