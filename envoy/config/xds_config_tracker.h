#pragma once

#include <string>
#include <vector>

#include "envoy/api/api.h"
#include "envoy/common/optref.h"
#include "envoy/common/pure.h"
#include "envoy/config/subscription.h"
#include "envoy/config/typed_config.h"
#include "envoy/event/dispatcher.h"
#include "envoy/protobuf/message_validator.h"
#include "envoy/service/discovery/v3/discovery.pb.h"

#include "source/common/protobuf/protobuf.h"

#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace Envoy {
namespace Config {

/**
 * The outcome of applying a single resource of an xDS update.
 */
enum class ResourceApplyStatus {
  // The resource was applied. Note that the resource types that warm up, namely clusters and
  // listeners, may still be warming when this is reported, so the resource is not necessarily
  // serving traffic yet.
  Applied,
  // Envoy left its configuration for this resource unchanged. Either the resource was identical to
  // the one already applied, or Envoy declined the update, for example because the name belongs to
  // a statically configured resource, or because listeners in that traffic direction are stopped.
  Skipped,
  // The resource could not be applied. The previously applied resource, if any, is retained.
  Failed,
  // The resource was removed.
  Removed,
};

/**
 * The outcome of applying a single resource of an xDS update, as reported to an XdsConfigTracker.
 *
 * All the string views reference memory owned by Envoy and are only valid for the duration of the
 * onResourcesApplied() call. Implementations must copy whatever they need to retain.
 */
struct ResourceApplyResult {
  // The resource name.
  absl::string_view name;
  // The version the resource was delivered with, whatever the outcome. Empty for removals, which
  // carry a resource name only.
  absl::string_view version;
  // The outcome for this resource.
  ResourceApplyStatus status;
  // Why the resource could not be applied. Only populated when status is
  // ResourceApplyStatus::Failed.
  absl::string_view details;
};

/**
 * An interface for hooking into xDS update events to provide the ability to use some external
 * processor in xDS update. This tracker provides the process point when the discovery response
 * is received, when the resources are successfully processed and applied, and when there is any
 * failure.
 *
 * Instance of this interface get invoked on the main Envoy thread. Thus, it is important
 * for implementations of this interface to not execute any blocking operations on the same
 * thread.
 */
class XdsConfigTracker {
public:
  virtual ~XdsConfigTracker() = default;

  /**
   * Invoked when SotW xDS configuration updates have been successfully parsed, applied on
   * the Envoy instance, and are about to be ACK'ed.
   *
   * For SotW, the passed resources contain all the received resources except for the heart-beat
   * ones in the original message. The call of this method means there is a subscriber for this
   * type_url and the type of resource is same as the message's type_url.
   *
   * Note: this method is called when *all* the resources in a response are accepted.
   *
   * @param type_url The type url of xDS message.
   * @param resources A list of decoded resources to add to the current state.
   */
  virtual void onConfigAccepted(const absl::string_view type_url,
                                const std::vector<DecodedResourcePtr>& resources) PURE;

  /**
   * Invoked when Delta xDS configuration updates have been successfully accepted, applied on
   * the Envoy instance, and are about to be ACK'ed.
   *
   * For Delta, added_resources contains all the received added resources except for the heart-beat
   * ones in the original message, and the removed resources are the same in the xDS message.
   *
   * Note: this method is called when *all* the resources in a response are accepted.
   *
   * @param type_url The type url of xDS message.
   * @param added_resources A list of decoded resources to add to the current state.
   * @param removed_resources A list of resources to remove from the current state.
   */
  virtual void
  onConfigAccepted(const absl::string_view type_url,
                   absl::Span<const envoy::service::discovery::v3::Resource* const> added_resources,
                   const Protobuf::RepeatedPtrField<std::string>& removed_resources) PURE;

  /**
   * Invoked after an xDS update was applied, with the outcome of every resource in the update.
   *
   * Unlike onConfigAccepted(), this is invoked whether or not all the resources were applied
   * successfully. Envoy applies the resources of an update one by one, so a single update can apply
   * some of its resources and reject the rest, in which case the update is NACKed even though part
   * of it took effect. This hook reports what became of each resource, so a tracker can tell the
   * management server which resources Envoy applied, skipped or removed, and why it rejected the
   * rest.
   *
   * Only CDS and LDS invoke this, including the on-demand CDS paths, which report one resource at
   * a time. They do so for every config source, so unlike onConfigAccepted() and
   * onConfigRejected(), which only the gRPC mux invokes, this is reported for a filesystem or REST
   * config source as well. For an update delivered over gRPC this is invoked before the matching
   * onConfigAccepted() or onConfigRejected() call.
   *
   * A removal that did not change anything is not reported. That covers a resource that was not
   * there, and one Envoy declines to remove, such as a statically configured cluster or one a
   * dynamic forward proxy owns; in neither case is the resource one the management server supplied
   * through this config source. Note that for State-of-the-World the set of removed resources is
   * derived by Envoy from everything it currently holds, rather than sent by the management
   * server. An update that did not act on any resource, such as a delta heartbeat, is not reported
   * either.
   *
   * @param type_url The type url of xDS message.
   * @param results The outcome of each resource in the update, in the order the resources were
   *        processed. Valid only for the duration of this call.
   */
  virtual void onResourcesApplied(const absl::string_view type_url,
                                  absl::Span<const ResourceApplyResult> results) PURE;

  /**
   * Invoked when xds configs are rejected during xDS ingestion.
   *
   * @param message The SotW discovery response message body.
   * @param details The process state and error details.
   */
  virtual void onConfigRejected(const envoy::service::discovery::v3::DiscoveryResponse& message,
                                const absl::string_view error_detail) PURE;

  /**
   * Invoked when xds configs are rejected during xDS ingestion.
   *
   * @param message The Delta discovery response message body.
   * @param details The process state and error details.
   */
  virtual void
  onConfigRejected(const envoy::service::discovery::v3::DeltaDiscoveryResponse& message,
                   const absl::string_view error_detail) PURE;

  /**
   * Invoked when the client unsubscribes from a resource of the given type. This is used to
   * track client-initiated unsubscriptions that do not result in server-side Delta removals.
   *
   * @param type_url The type url of xDS message.
   * @param resources A resource name that the client unsubscribed from.
   */
  virtual void onResourceUnsubscribed(const absl::string_view type_url,
                                      absl::string_view resource) PURE;
};

using XdsConfigTrackerPtr = std::unique_ptr<XdsConfigTracker>;
using XdsConfigTrackerOptRef = OptRef<XdsConfigTracker>;

/**
 * A factory abstract class for creating instances of XdsConfigTracker.
 */
class XdsConfigTrackerFactory : public Config::TypedFactory {
public:
  ~XdsConfigTrackerFactory() override = default;

  /**
   * Creates an XdsConfigTracker using the given config.
   */
  virtual XdsConfigTrackerPtr
  createXdsConfigTracker(const Protobuf::Any& config,
                         ProtobufMessage::ValidationVisitor& validation_visitor, Api::Api& api,
                         Event::Dispatcher& dispatcher) PURE;

  std::string category() const override { return "envoy.config.xds_tracker"; }
};

} // namespace Config
} // namespace Envoy
