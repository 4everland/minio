// Copyright (c) 2015-2021 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package redis

import (
	"github.com/minio/minio/internal/config"
	"github.com/minio/minio/internal/event/target"
)

// etcd config documented in default config
var (
	defaultHelpPostfix = func(key string) string {
		return config.DefaultHelpPostfix(DefaultKVS, key)
	}

	Help = config.HelpKVS{
		config.HelpKV{
			Key:         target.RedisAddress,
			Description: "Redis server's address. For example: `localhost:6379`",
			Type:        "address",
			Sensitive:   true,
		},
		config.HelpKV{
			Key:         target.RedisPassword,
			Description: "Redis server password",
			Optional:    true,
			Type:        "string",
			Sensitive:   true,
		},
	}
)
