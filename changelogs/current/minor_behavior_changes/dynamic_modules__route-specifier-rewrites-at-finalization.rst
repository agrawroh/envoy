The :ref:`dynamic modules route specifier <config_http_route_specifiers_dynamic_modules>` now applies
the ``regex_rewrite`` of a selected route override when the request headers are finalized, to the path
the request carries then, rather than computing it when the decision resolves. The rewrite sets
``x-envoy-original-path`` exactly as a configured route does, overwriting a value the request already
carries where before an existing value was kept. A route reused with the ``ReusePrevious`` decision
now rewrites the current path of the request rather than the path of the request it was built for.
