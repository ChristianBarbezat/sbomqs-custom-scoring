// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package omniborid

import "regexp"

type OMNIBORID string

const omniRegex = `^gitoid:blob:sha1:[a-fA-F0-9]{40}$`

func (omni OMNIBORID) Valid() bool {
	return regexp.MustCompile(omniRegex).MatchString(omni.String())
}

func NewOmni(omni string) OMNIBORID {
	return OMNIBORID(omni)
}

func (omni OMNIBORID) String() string {
	return string(omni)
}
