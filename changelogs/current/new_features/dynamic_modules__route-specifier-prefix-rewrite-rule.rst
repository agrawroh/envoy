Added ``set_prefix_rewrite_rule`` to the :ref:`dynamic modules route specifier
<config_http_route_specifiers_dynamic_modules>`. It records a prefix rewrite as a rule that is applied
to the path the request carries when the request headers are finalized, the same way the
``prefix_rewrite`` of a configured route is applied, so a route that carries it is not specific to the
request it was built for. The regex rewrite of a selected route override is now applied at finalization
as well, rather than computed when the decision resolves. A rewrite that does not apply at finalization
leaves the path unchanged and is counted in ``rewrite_not_applied``.
