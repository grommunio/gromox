#pragma once
#include <memory>
#include <gromox/mime.hpp>

struct GX_EXPORT MIME_POOL {
	static std::shared_ptr<MIME_POOL> create() try {
		return std::make_shared<MIME_POOL>();
	} catch (const std::bad_alloc &) {
		return nullptr;
	}
	static MIME *get_mime() try {
		return new MIME();
	} catch (const std::bad_alloc &) {
		return nullptr;
	}
	static void put_mime(MIME *p) { delete p; }
};
