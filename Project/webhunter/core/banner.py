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

import pyfiglet
from termcolor import colored
from typing import Optional

def show_banner(custom_text: Optional[str] = None):
    banner_text = custom_text or "Web-Hunter"
    banner = pyfiglet.figlet_format(banner_text)
    colored_banner = colored(banner, 'red', attrs=['bold'])
    
    print(colored_banner)
    print(colored("Created by Nabaraj Lamichhane", 'yellow'))
    print(colored("\nCAUTION:", 'red', attrs=['bold']))
    print(colored("Use it for ethical purposes only. If your government does not recommend", 'red'))
    print(colored("these types of tools, avoid using them. Try at your own risk.\n", 'red'))
    print(colored("=" * 80 + "\n", 'white'))

