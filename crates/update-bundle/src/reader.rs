//! Lecteur streaming de bundles.
//!
//! Spécification : `docs/spec/02-bundle-format.md` §4.
//!
//! Le BundleReader extrait le header, puis itère sur les chunks
//! un par un, en calculant les offsets dynamiquement.

use crate::errors::{BundleError, ParseError};
use crate::types::{BundleChunk, BundleHeader};

/// Lecteur streaming d'un bundle.
///
/// Extrait le header depuis les données brutes, puis permet d'itérer
/// sur les chunks un par un. Les chunks sont lus par offsets calculés
/// depuis le header (`chunk_count`, `chunk_size`).
pub struct BundleReader {
    /// Header parsé.
    header: BundleHeader,
    /// Données brutes du bundle (header + content).
    ///
    /// **Note** : en production, cette implémentation devrait lire depuis un
    /// `std::io::Read` (fichier, socket) pour éviter de charger l'intégralité
    /// du bundle en mémoire. Cette version avec `Vec<u8>` est une version
    /// de développement pour faciliter les tests.
    data: Vec<u8>,
}

impl BundleReader {
    /// Construit un lecteur depuis des données brutes.
    ///
    /// Parse le header en première étape. Les données doivent contenir
    /// au minimum un header complet.
    ///
    /// # Erreurs
    ///
    /// - `ParseError::HeaderTooShort` si les données sont inférieures à la taille du header
    /// - `ParseError::InvalidMagic` si le magic number ne correspond pas
    pub fn new(data: &[u8]) -> Result<BundleReader, ParseError> {
        let header = BundleHeader::parse(data)?;
        Ok(BundleReader {
            header,
            data: data.to_vec(),
        })
    }

    /// Retourne le header parsé.
    pub fn header(&self) -> &BundleHeader {
        &self.header
    }

    /// Retourne l'identifiant unique du bundle.
    pub fn bundle_id(&self) -> &[u8; 32] {
        self.header.bundle_id()
    }

    /// Itère sur les chunks du bundle.
    ///
    /// Chaque chunk est lu à son offset calculé (`chunk_size * index`).
    pub fn chunks(&mut self) -> BundleChunkIterator<'_> {
        let count = self.header.chunk_count();
        BundleChunkIterator {
            reader: self,
            remaining: count,
        }
    }

    /// Retourne le nombre de chunks dans le bundle.
    pub fn chunk_count(&self) -> u32 {
        self.header.chunk_count()
    }

    /// Retourne la taille des données totales du bundle.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }
}

/// Itérateur sur les chunks déchiffrés d'un bundle.
pub struct BundleChunkIterator<'a> {
    reader: &'a mut BundleReader,
    remaining: u32,
}

impl Iterator for BundleChunkIterator<'_> {
    type Item = Result<u32, BundleError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }

        let chunk_index = self.reader.header.chunk_count() - self.remaining;
        let chunk_size = self.reader.header.chunk_size() as usize;

        // Calculer l'offset du chunk dans les données brutes.
        // Utiliser checked_mul pour éviter un overflow silencieux.
        #[allow(clippy::cast_possible_truncation)]
        let chunk_offset = chunk_size.checked_mul(chunk_index as usize)?;

        let Some(chunk_data_start) =
            (self.reader.header.header_size as usize).checked_add(chunk_offset)
        else {
            self.remaining -= 1;
            return Some(Err(BundleError::Parse(ParseError::ChunkTooBig {
                got: self.reader.header.chunk_size(),
            })));
        };

        let Some(chunk_data_end) = chunk_data_start.checked_add(chunk_size) else {
            self.remaining -= 1;
            return Some(Err(BundleError::Parse(ParseError::ChunkTooBig {
                got: self.reader.header.chunk_size(),
            })));
        };

        if chunk_data_end > self.reader.data.len() {
            self.remaining -= 1;
            return Some(Err(BundleError::Parse(ParseError::ChunkTooLarge {
                got: chunk_size,
                need: self
                    .reader
                    .data
                    .len()
                    .saturating_sub(self.reader.header.header_size as usize),
            })));
        }

        #[allow(clippy::indexing_slicing)]
        let chunk_data = &self.reader.data[chunk_data_start..chunk_data_end];

        // Parser le chunk
        match BundleChunk::parse(chunk_data) {
            Ok(chunk) => {
                self.remaining -= 1;
                Some(Ok(chunk.data_length()))
            }
            Err(e) => {
                self.remaining -= 1;
                Some(Err(BundleError::Parse(e)))
            }
        }
    }
}
