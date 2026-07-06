Fixed a use-after-free in the dynamic module cluster load balancer's asynchronous host selection.
The cancellation flag and worker dispatcher were stored on the load balancer, so a second host
selection on the same worker overwrote the first selection's state and a synchronous selection
cleared it. A cancelled or superseded selection could then complete on an already-destroyed
request context. The per-selection state is now keyed by the load balancer context, so each
completion reads the state of the selection it belongs to.
