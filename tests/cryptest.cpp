// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2021 grommunio GmbH
// This file is part of Gromox.
#include <gromox/util.hpp>
using namespace gromox;
int main()
{
	printf("%s\n", crypt_wrapper("test"));
	return 0;
}
