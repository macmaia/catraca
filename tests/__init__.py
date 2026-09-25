import warnings

# Most tests build gates without an evidence log on purpose. test_evidence
# checks the warning itself.
warnings.filterwarnings("ignore", message="Gate built without an evidence log")
