/*
 * Copyright (C) 2021, Xilinx Inc - All rights reserved
 * Xilinx Lookahead XMA Plugin
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You may
 * not use this file except in compliance with the License. A copy of the
 * License is located at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

 # xma_xlnx_lookahead

This repository contains the XMA plugins that talk to the Xilinx U30 Look-Ahead IP.

The XMA plugins need to be compiled against xvbm, as xvbm provides the necessary zero-copy support for buffer movement.
