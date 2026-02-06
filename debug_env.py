import sys
import importlib.metadata

def check_package(package):
    try:
        version = importlib.metadata.version(package)
        print(f"✅ {package}: {version}")
    except importlib.metadata.PackageNotFoundError:
        print(f"❌ {package}: NOT INSTALLED")

print(f"Python: {sys.version}")
check_package("gradio")
check_package("gradio_client")
check_package("pydantic")
