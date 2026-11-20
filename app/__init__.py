try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass
