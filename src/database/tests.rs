#[cfg(test)]
mod database_tests {
    use crate::database::bytes_to_message;
use crate::database::bytes_to_identity;
    use crate::database::message_to_bytes;
    use crate::database::Message;
    use crate::database::{
        get_identity_database_handle, get_message_database_handle, identity_to_bytes, Identity,
    };
    #[test]
    fn test_get_identity_database_handle() {
        get_identity_database_handle();
    }

    #[test]
    fn test_get_message_database_handle() {
        get_message_database_handle();
    }

    #[test]
    fn test_identity_to_bytes() {
        identity_to_bytes(
            &(Identity {
                identity_id: [0; 32],
                fingerprint: [0; 32],
                public_key: [0; 1024],
            }),
        );
    }

    #[test]
    fn test_bytes_to_identity() {
        let id: Identity = Identity {
            identity_id: [0; 32],
            fingerprint: [0; 32],
            public_key: [0; 1024],
        };
        let idn: Identity = bytes_to_identity(identity_to_bytes(&id));
        assert_eq!(id.identity_id, idn.identity_id);
    }

    #[test]
    fn test_message_to_bytes() {
        let msg: Message = Message {
            sender_id: [0; 32],
            fingerprint: [0; 32],
            message: [0; 1024],
            signature: [0; 1024],
            public_key: [0; 1024],
            recipient_id: [0; 32],
        };
        message_to_bytes(&msg);
    }

    #[test]
    fn test_bytes_to_message() {
        let msg: Message = Message {
            sender_id: [0; 32],
            fingerprint: [0; 32],
            message: [0; 1024],
            signature: [0; 1024],
            public_key: [0; 1024],
            recipient_id: [0; 32],
        };
        let msgn: Message = bytes_to_message(message_to_bytes(&msg));
        assert_eq!(msg.sender_id, msgn.sender_id);
    }
}
