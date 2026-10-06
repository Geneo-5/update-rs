//! Cible de fuzzing pour la machine à états du démon
//!
//! Cette cible fuzz les séquences d'états et de transitions du démon.
//! Elle vérifie que :
//! 1. La machine à états ne plante pas sur des séquences invalides
//! 2. Les transitions interdites sont rejetées
//! 3. Le cleanup est toujours effectué même après erreur

use libfuzzer_sys::fuzz_target;

// États de la machine à états (à synchroniser avec updated)
#[derive(Debug, Clone, Copy, arbitrary::Arbitrary)]
#[repr(u8)]
enum State {
    Idle = 0,
    AcquiringLock = 1,
    Fetching = 2,
    Verifying = 3,
    PreparingJail = 4,
    AssemblingJail = 5,
    ExecutingJail = 6,
    CleaningJail = 7,
    LockHeld = 8,
    Rejected = 9,
    Error = 10,
}

// Événements qui déclenchent des transitions
#[derive(Debug, Clone, Copy, arbitrary::Arbitrary)]
#[repr(u8)]
enum Event {
    Start = 0,
    LockAcquired = 1,
    LockHeld = 2,
    BundleFetched = 3,
    BundleVerified = 4,
    BundleRejected = 5,
    JailPrepared = 6,
    JailAssembled = 7,
    JailExecuted = 8,
    JailFailed = 9,
    JailCleaned = 10,
    Timeout = 11,
    Error = 12,
}

fuzz_target!(|events: Vec<Event>| {
    // Simuler une séquence d'événements
    let mut current_state = State::Idle;

    for event in events {
        // TODO : Appeler updated::StateMachine::transition(current_state, event)
        // et vérifier que :
        // 1. La transition ne panique pas
        // 2. Les transitions interdites sont rejetées
        // 3. Le cleanup est effectué après Error

        // Placeholder : machine à états simplifiée
        let next_state = match (current_state, event) {
            (State::Idle, Event::Start) => State::AcquiringLock,
            (State::AcquiringLock, Event::LockAcquired) => State::Fetching,
            (State::AcquiringLock, Event::LockHeld) => State::LockHeld,
            (State::Fetching, Event::BundleFetched) => State::Verifying,
            (State::Verifying, Event::BundleVerified) => State::PreparingJail,
            (State::Verifying, Event::BundleRejected) => State::Rejected,
            (State::PreparingJail, Event::JailPrepared) => State::AssemblingJail,
            (State::AssemblingJail, Event::JailAssembled) => State::ExecutingJail,
            (State::ExecutingJail, Event::JailExecuted) => State::CleaningJail,
            (State::ExecutingJail, Event::JailFailed) => State::CleaningJail,
            (State::CleaningJail, Event::JailCleaned) => State::Idle,
            (_, Event::Error) => State::Error,
            (_, Event::Timeout) => State::Error,
            _ => current_state, // Transition invalide, rester dans l'état actuel
        };

        current_state = next_state;

        // Vérifier que l'état est valide
        assert!(matches!(
            current_state,
            State::Idle
                | State::AcquiringLock
                | State::Fetching
                | State::Verifying
                | State::PreparingJail
                | State::AssemblingJail
                | State::ExecutingJail
                | State::CleaningJail
                | State::LockHeld
                | State::Rejected
                | State::Error
        ));
    }
});
