# Copyright 2025 nabar
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pytest
import asyncio
from pathlib import Path

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
def test_output_dir():
    test_dir = Path("c:/Users/nabar/OneDrive/Desktop/Project/results/test")
    test_dir.mkdir(parents=True, exist_ok=True)
    yield test_dir
    # Cleanup after tests
    for file in test_dir.glob("*"):
        file.unlink()
    test_dir.rmdir()

