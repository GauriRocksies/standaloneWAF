"""
waf_integration

Django-specific glue between the framework-independent waf_core
package and this project's Django app (blocklist model, attack
persistence, WSGI request objects). Nothing in waf_core imports
anything from this package — the dependency only goes one way.

    Django HttpRequest
          |
          v
    waf_integration.django_adapter.to_waf_request()
          |
          v
    waf_core.WAFRequest
          |
          v
    waf_core.WAFEngine.inspect()
          |
          v
    waf_core.Decision  --(on_detection hook)-->  waf.logging.attack_logger.log_attack()
"""
