from setuptools import setup, find_packages

if __name__ == "__main__":
    setup(
        name="cvss_calculator",
        packages=find_packages("src", include=["cvss_calculator*"]),
        package_dir={"": "src"},
        description="Python library that allows you to calculate score cvss 2 and 3 versions by fstec",
        version="1.0"
    )
