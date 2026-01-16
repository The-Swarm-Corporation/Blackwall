from swarms import BaseTool



def block_ip_address(ip_address: str) -> str:
    """
    Block an IP address
    """
    return f"IP address {ip_address} blocked"


schema = BaseTool().function_to_dict(block_ip_address)

print(schema)