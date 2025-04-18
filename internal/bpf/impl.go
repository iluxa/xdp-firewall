/*
 * Copyright (C) 2025 Ilya Gavrilov <gilyav@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

package bpf

import (
	"fmt"
)

func (fw *FwCidrKey) String() string {
	return fmt.Sprintf("Id: %d, PrefixLen: %d, Addr: %d", fw.Id, fw.PrefixLen, fw.Addr)
}

func (fw *FwCidrValue) String() string {
	return fmt.Sprintf("InnerId: %d, NextCidr: %s", fw.InnerId, fw.NextCidr.String())
}

func (fw *FwPortKey) String() string {
	return fmt.Sprintf("Id: %d, Port: %d", fw.Id, fw.Port)
}

func (fw *FwProtoKey) String() string {
	return fmt.Sprintf("Id: %d, Proto: %d", fw.Id, fw.Proto)
}

func (fw *FwRuleAttrs) String() string {
	return fmt.Sprintf("Action: %d, Id: %d, Priority: %d", fw.Action, fw.Id, fw.Priority)
}
