try {
                        ManualRSAEncryption.performHybridEncryption(scanner);
                    } catch (Exception e) {
                        System.err.println("An error occurred during hybrid encryption: " + e.getMessage());
                        e.printStackTrace();
                    }
