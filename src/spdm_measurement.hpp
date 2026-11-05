#pragma once
/**
 * @file spdm_measurement.hpp
 * @brief Fetches signed SPDM measurements from the responder(s) exposed by
 *        spdmd over D-Bus (xyz.openbmc_project.Attestation.MeasurementSet).
 *
 * To be used by SpdmAttestationStrategy (spdm_attestation.hpp).
 */
#include "beastdefs.hpp"
#include "logger.hpp"
#include "sdbus_calls.hpp"

#include <xyz/openbmc_project/Attestation/MeasurementSet/common.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace NSNAME
{
namespace spdm_measurement
{
using MeasurementSetCommon =
    sdbusplus::common::xyz::openbmc_project::attestation::MeasurementSet;

/// SPDM measurement indices requested from the responder. Index 0 is the
/// "total count" sentinel and must not be mixed with specific indices.
inline const std::vector<size_t> defaultIndices{1, 2, 3, 4};

/// SPDM slot 0: platform certificate exchange.
constexpr size_t platformCertSlot = 0;
/// SPDM slot 1: SPDM certificate and measurements. Signed measurements are
/// requested on this slot.
constexpr size_t measurementSlot = 1;

/** Reply of SPDMGetSignedMeasurements. */
struct SignedMeasurements
{
    sdbuscompat::object_path certPath;
    std::string hashAlgo;    ///< e.g. "SHA256", "SHA384"
    std::string certPem;     ///< responder certificate (PEM)
    std::string measurement; ///< base64 of the measurement blocks + signature
    std::string signAlgo;    ///< e.g. "ECDSA_P256"
    std::string version;
    std::vector<uint8_t> opaqueData; ///< TPM quote frames, may be empty
};

/**
 * Call SPDMGetSignedMeasurements for @p slotId on one MeasurementSet object.
 *
 * An empty nonce makes libspdm generate a fresh nonce per DSP0274.
 *
 * @return the reply, or std::nullopt if the D-Bus call failed.
 */
inline net::awaitable<std::optional<SignedMeasurements>> getSignedMeasurements(
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string service,
    std::string objPath, size_t slotId, std::vector<size_t> indices)
{
    const std::string nonce{};
    auto [ec, certPath, hashAlgo, certPem, measurement, signAlgo, version,
          opaqueData] =
        co_await awaitable_dbus_method_call<
            sdbuscompat::object_path, std::string, std::string, std::string,
            std::string, std::string, std::vector<uint8_t>>(
            *conn, service, objPath, MeasurementSetCommon::interface,
            MeasurementSetCommon::method_names::spdm_get_signed_measurements,
            indices, nonce, slotId);
    if (ec)
    {
        LOG_ERROR("[slot={}] SPDMGetSignedMeasurements on {} failed: {}",
                  slotId, objPath, ec.message());
        co_return std::nullopt;
    }

    LOG_INFO("[slot={}] version={} hashAlgo={} signAlgo={} opaque={} bytes",
             slotId, version, hashAlgo, signAlgo, opaqueData.size());
    co_return SignedMeasurements{
        std::move(certPath),    std::move(hashAlgo), std::move(certPem),
        std::move(measurement), std::move(signAlgo), std::move(version),
        std::move(opaqueData)};
}

/** Find every object implementing the MeasurementSet interface. */
inline net::awaitable<SubTreeMap> findMeasurementSets(
    std::shared_ptr<sdbusplus::asio::connection> conn)
{
    auto [ec, subtree] = co_await getSubTree(
        *conn, "/", 0, {std::string(MeasurementSetCommon::interface)});
    if (ec)
    {
        LOG_WARNING("GetSubTree for MeasurementSet failed: {}", ec.message());
        co_return SubTreeMap{};
    }
    co_return subtree;
}

/**
 * Get the measurements of one responder.
 *
 * Calls SPDMGetSignedMeasurements on slot 0 (platform certificate exchange)
 * and then on slot 1 (SPDM certificate and measurements). Only the slot 1
 * reply is returned; a slot 0 failure is logged and does not affect it.
 *
 * @return the slot 1 reply, or std::nullopt if the slot 1 call failed.
 */
inline net::awaitable<std::optional<SignedMeasurements>> getMeasurement(
    std::shared_ptr<sdbusplus::asio::connection> conn, std::string service,
    std::string objPath)
{
    auto slot0 = co_await getSignedMeasurements(
        conn, service, objPath, platformCertSlot, defaultIndices);
    if (!slot0)
    {
        LOG_WARNING("Slot 0 measurements of {} unavailable", objPath);
    }
    co_return co_await getSignedMeasurements(conn, service, objPath,
                                             measurementSlot, defaultIndices);
}
} // namespace spdm_measurement
} // namespace NSNAME
