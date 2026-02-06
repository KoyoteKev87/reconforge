import sys
import os

# Ensure src is in path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.ui import build_ui

def main():
    print("🦅 ReconForge v1.1 (Shared Mode) Starting...")
    try:
        demo = build_ui()
        # Enable queue for generator outputs
        demo.queue()
        # share=True fulfills PRD requirement for sharable link and prevents localhost binding errors
        print("launching with share=True...")
        demo.launch(inbrowser=True, share=True)
    except Exception as e:
        print(f"❌ Launch Error: {e}")
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()
