from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.style import Style
from rich import box
import time
import sys

def show_banner():
    console = Console()
    
    # VIP Banner text
    banner_text = """
    ██╗    ██╗███████╗██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██║    ██║██╔════╝██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║ █╗ ██║█████╗  ██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██║███╗██║██╔══╝  ██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ╚███╔███╔╝███████╗██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
     ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    """
    
    # Luxury gold gradient colors
    colors = [
        "yellow",
        "yellow1",
        "gold1",
        "orange3",
        "dark_orange",
        "orange4"
    ]
    
    # Create animated panel
    def create_panel(color):
        return Panel(
            Text(banner_text, style=f"bold {color}"),
            box=box.HEAVY,
            border_style=f"bold {color}",
            title="[bold]VIP Edition[/bold]",
            subtitle="[bold]Advanced Web Reconnaissance Tool[/bold]"
        )
    
    # Animation effect
    try:
        for color in colors:
            console.clear()
            console.print(create_panel(color))
            time.sleep(0.2)
        
        # Final static display with additional info
        console.clear()
        final_panel = create_panel("gold1")
        console.print(final_panel)
        console.print("\n[bold gold1]✨ Welcome to WebHunter VIP Edition ✨[/bold gold1]")
        console.print("[dim]Created by nabar[/dim]\n")
        
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    show_banner()

