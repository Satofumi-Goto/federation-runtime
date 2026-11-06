// Candidate-only registry aligned with Seneschal's selectable Map layers.
// This is NOT an egress allowlist, a data-provider connection or an Activity source directory.
// All candidate IDs are inert until Activity source-owner review and a separate cutover PR.
const publicOsm = [
 'chargespot','umbrella','toilet','smoking','water','aed','freeWifi','babyCare',
 'bikeCare','parcelLocker','workBooth','strollerRental','carShare','bagStorage',
 'atm','trash','rest','recycling','publicPhone','shower','laundry','elevator','shelter',
];
const municipalityPending = ['coolingShelter','emergencyWater'];
const operatorPending = ['reservedParking'];
export const AMENITY_CANDIDATES = Object.freeze([
 ...publicOsm.map(mapLayerId => ({mapLayerId,sourceKind:'osm-registered-location',sourceOwner:'activity'})),
 ...municipalityPending.map(mapLayerId => ({mapLayerId,sourceKind:'municipal-authorized-feed-pending',sourceOwner:'activity'})),
 ...operatorPending.map(mapLayerId => ({mapLayerId,sourceKind:'operator-authorized-feed-pending',sourceOwner:'activity'})),
].map(candidate => Object.freeze({
 ...candidate,
 mode:'catalog-candidate-only',
 gatewayRouteId:null,
 gatewayConsumerActive:false,
 egressEnabled:false,
 liveVerified:false,
 cutoverApproved:false,
})));
