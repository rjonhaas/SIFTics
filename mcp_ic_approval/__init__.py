"""SIFTics IC Authority Gate MCP server.

Exposes:
    request_approval         agent → propose an action; writes pending request
    check_approval           agent → poll for IC decision
    execute_hunt_package     agent → execute (requires valid signed approval)
    escalate_to_cold         agent → run cold-path Plaso/Volatility (requires approval)
    isolate_host             agent → push isolation via Velociraptor (requires approval)

Architectural guarantee — there is intentionally NO:
    • sign_approval()        signing happens out-of-band via sift-approve CLI / UI
    • execute_unapproved_*() actions only run with a signed ICApproval object
    • read_ic_key()          IC key material is not on the MCP surface
"""
__version__ = "0.1.0"
